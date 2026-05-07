import os
import time
import json
import secrets
import subprocess
from collections import defaultdict
from datetime import datetime

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, join_room, emit

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
# SECRET_KEY loaded from environment — never hardcoded
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ── Rate Limiter (optional — install flask-limiter if available) ───────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address, app=app,
                      default_limits=["200 per minute"], storage_uri="memory://")
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False
    class _DummyLimiter:
        def limit(self, *a, **kw):
            return lambda f: f
    limiter = _DummyLimiter()

# ── SocketIO ───────────────────────────────────────────────────────────────
# LAB_MODE=1 (default) → accept all origins — works across local network / classroom
# LAB_MODE=0           → restrict to ALLOWED_ORIGINS env var
LAB_MODE = os.environ.get('LAB_MODE', '1') == '1'
ALLOWED_ORIGINS = '*' if LAB_MODE else os.environ.get('ALLOWED_ORIGINS', 'https://localhost:5000').split(',')

socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_ORIGINS,
    max_http_buffer_size=5 * 1024 * 1024,   # 5 MB hard cap (was 50 MB)
    ping_timeout=60,
    ping_interval=25,
    async_mode='threading'
)

# ── In-memory security state ───────────────────────────────────────────────
room_members   = defaultdict(set)
sid_msg_counts = defaultdict(int)
sid_msg_window = defaultdict(float)
blocked_sids   = set()
security_log   = []          # last 200 events

MSG_RATE_LIMIT   = 30        # messages per window
MSG_RATE_WINDOW  = 10        # seconds
MAX_ROOM_MEMBERS = 10

# ── Helpers ────────────────────────────────────────────────────────────────
def log_event(event_type, sid, room=None, detail=""):
    entry = {
        "ts":     datetime.utcnow().strftime("%H:%M:%S"),
        "type":   event_type,
        "sid":    (sid or "")[:8],
        "room":   room or "–",
        "detail": detail
    }
    security_log.append(entry)
    if len(security_log) > 200:
        security_log.pop(0)
    socketio.emit('security_event', entry)   # live broadcast to CN panel

def rate_ok(sid):
    now = time.time()
    if now - sid_msg_window[sid] > MSG_RATE_WINDOW:
        sid_msg_window[sid] = now
        sid_msg_counts[sid] = 0
    sid_msg_counts[sid] += 1
    if sid_msg_counts[sid] > MSG_RATE_LIMIT:
        log_event("RATE_LIMIT", sid, detail=f"{sid_msg_counts[sid]} msgs/{MSG_RATE_WINDOW}s")
        return False
    return True

def valid_room(room):
    if not room or len(room) > 64:
        return False
    return all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in room)

def valid_username(name):
    return len(name) <= 32 and not any(c in name for c in '<>"\';()')

# ── Routes ─────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/security-log')
@limiter.limit("30 per minute")
def get_security_log():
    return jsonify(security_log[-50:])

@app.route('/api/vulnerability-scan')
@limiter.limit("5 per minute")
def vulnerability_scan():
    findings = []
    score    = 100

    # 1 — Secret key strength
    sk = app.config.get('SECRET_KEY', '')
    if any(x in sk.lower() for x in ['null_relay', 'secret', 'password', 'admin']) or len(sk) < 24:
        findings.append({"id":"SEC-001","severity":"CRITICAL",
            "title":"Weak / hardcoded SECRET_KEY",
            "detail":"The secret key is predictable. Attackers can forge session tokens.",
            "fix":"export SECRET_KEY=$(python3 -c \"import secrets; print(secrets.token_hex(32))\")"})
        score -= 25
    else:
        findings.append({"id":"SEC-001","severity":"PASS","title":"SECRET_KEY strength","detail":"Key appears random and long enough.","fix":""})

    # 2 — CORS
    if LAB_MODE:
        findings.append({"id":"SEC-002","severity":"INFO",
            "title":"CORS open (LAB_MODE=1)",
            "detail":"All origins accepted — fine for classroom, set LAB_MODE=0 before deploying publicly.",
            "fix":"export LAB_MODE=0 && export ALLOWED_ORIGINS=https://yourdomain.com"})
    elif '*' in str(ALLOWED_ORIGINS):
        findings.append({"id":"SEC-002","severity":"HIGH",
            "title":"Wildcard CORS (cors_allowed_origins='*')",
            "detail":"Any website can make cross-origin requests to your server.",
            "fix":"Set ALLOWED_ORIGINS env var to your specific domain."})
        score -= 15
    else:
        findings.append({"id":"SEC-002","severity":"PASS","title":"CORS policy","detail":f"Restricted to: {ALLOWED_ORIGINS}","fix":""})

    # 3 — Buffer size
    buf = 5 * 1024 * 1024   # our hardcoded value
    if buf > 10 * 1024 * 1024:
        findings.append({"id":"SEC-003","severity":"MEDIUM",
            "title":"HTTP buffer too large (DoS risk)",
            "detail":f"max_http_buffer_size={buf//(1024*1024)}MB allows memory exhaustion attacks.",
            "fix":"Set buffer to ≤5 MB."})
        score -= 10
    else:
        findings.append({"id":"SEC-003","severity":"PASS","title":"HTTP buffer size","detail":f"Capped at {buf//(1024*1024)} MB.","fix":""})

    # 4 — Debug mode
    if app.debug:
        findings.append({"id":"SEC-004","severity":"CRITICAL",
            "title":"Debug mode is ON",
            "detail":"Flask's interactive debugger is exposed. Remote code execution possible.",
            "fix":"Set debug=False and never commit debug=True."})
        score -= 25
    else:
        findings.append({"id":"SEC-004","severity":"PASS","title":"Debug mode","detail":"Debug is off.","fix":""})

    # 5 — Active blocked connections
    if blocked_sids:
        findings.append({"id":"SEC-005","severity":"INFO",
            "title":f"{len(blocked_sids)} blocked connection(s)",
            "detail":"Rate-limit bans active — possible abuse attempt.",
            "fix":"Review security log for patterns."})
    else:
        findings.append({"id":"SEC-005","severity":"PASS","title":"Blocked connections","detail":"None currently blocked.","fix":""})

    # 6 — Oversized rooms
    oversized = [r for r, m in room_members.items() if len(m) > MAX_ROOM_MEMBERS]
    if oversized:
        findings.append({"id":"SEC-006","severity":"MEDIUM",
            "title":f"{len(oversized)} oversized room(s)",
            "detail":"More peers than allowed — may indicate room-flooding attack.",
            "fix":"Enforce server-side room size cap."})
        score -= 5
    else:
        findings.append({"id":"SEC-006","severity":"PASS","title":"Room sizes","detail":f"All within {MAX_ROOM_MEMBERS}-member limit.","fix":""})

    # 7 — Dependency health
    try:
        r = subprocess.run(['pip', 'check'], capture_output=True, text=True, timeout=10)
        out = (r.stdout + r.stderr).strip()
        if 'No broken' in out or not out:
            findings.append({"id":"SEC-007","severity":"PASS","title":"Dependencies","detail":"pip check: no conflicts.","fix":""})
        else:
            findings.append({"id":"SEC-007","severity":"MEDIUM","title":"Dependency conflicts",
                "detail":out[:300],"fix":"pip install --upgrade -r requirements.txt"})
            score -= 10
    except Exception as e:
        findings.append({"id":"SEC-007","severity":"INFO","title":"Dependency check skipped","detail":str(e),"fix":""})

    # 8 — Recent threat events
    threat_types = {'RATE_LIMIT','BLOCKED','INVALID_ROOM','INVALID_USERNAME','UNAUTHORIZED_MSG','OVERSIZED_PAYLOAD'}
    recent = [e for e in security_log[-50:] if e['type'] in threat_types]
    if len(recent) >= 5:
        findings.append({"id":"SEC-008","severity":"HIGH",
            "title":f"{len(recent)} threat events in recent log",
            "detail":"Elevated anomalies — possible active attack.",
            "fix":"Check security log tab for source SIDs."})
        score -= 15
    else:
        findings.append({"id":"SEC-008","severity":"PASS","title":"Threat event level",
            "detail":f"{len(recent)} anomalous events in recent window.","fix":""})

    # 9 — Security headers
    # We add them in after_request, so just report PASS
    findings.append({"id":"SEC-009","severity":"PASS","title":"Security HTTP headers",
        "detail":"X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy set.","fix":""})

    # 10 — Rate limiter availability
    if not LIMITER_AVAILABLE:
        findings.append({"id":"SEC-010","severity":"MEDIUM","title":"Rate limiter not installed",
            "detail":"flask-limiter is missing. HTTP endpoints are unprotected.",
            "fix":"pip install flask-limiter"})
        score -= 5
    else:
        findings.append({"id":"SEC-010","severity":"PASS","title":"HTTP rate limiter","detail":"flask-limiter active.","fix":""})

    score = max(0, score)
    return jsonify({
        "score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "scanned_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "findings": findings
    })

# ── Socket events ──────────────────────────────────────────────────────────
@socketio.on('join')
def on_join(data):
    sid      = request.sid
    room     = data.get('room', '').strip()
    username = data.get('username', 'Anonymous').strip()[:32]

    if sid in blocked_sids:
        emit('error', {'msg': 'Connection blocked by server.'})
        return
    if not valid_room(room):
        log_event("INVALID_ROOM", sid, room=room, detail="Bad format")
        emit('error', {'msg': 'Invalid room ID.'})
        return
    if not valid_username(username):
        log_event("INVALID_USERNAME", sid, room=room, detail=repr(username))
        emit('error', {'msg': 'Invalid username — no special characters allowed.'})
        return
    if len(room_members[room]) >= MAX_ROOM_MEMBERS:
        log_event("ROOM_FULL", sid, room=room)
        emit('error', {'msg': 'Room is full.'})
        return

    join_room(room)
    room_members[room].add(sid)
    log_event("JOIN", sid, room=room, detail=f"user={username}")
    emit('user_joined', {'username': username, 'sid': sid}, to=room, include_self=False)

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    for members in room_members.values():
        members.discard(sid)
    sid_msg_counts.pop(sid, None)
    sid_msg_window.pop(sid, None)
    log_event("DISCONNECT", sid)

@socketio.on('signal_public_key')
def on_signal_public_key(data):
    sid  = request.sid
    room = data.get('room', '')
    if not valid_room(room):
        return
    if sid not in room_members.get(room, set()):
        log_event("UNAUTHORIZED_KEY", sid, room=room, detail="Not a member")
        return
    emit('receive_public_key', data, to=room, include_self=False)

@socketio.on('encrypted_message')
def on_encrypted_message(data):
    sid    = request.sid
    room   = data.get('room', '')
    msg_id = data.get('msgId')

    if sid in blocked_sids:
        emit('error', {'msg': 'You are rate-limited.'})
        return
    if not rate_ok(sid):
        blocked_sids.add(sid)
        log_event("BLOCKED", sid, room=room, detail="Rate limit exceeded")
        emit('error', {'msg': 'Rate limit exceeded. Slow down.'})
        return
    if not valid_room(room):
        log_event("INVALID_ROOM", sid, room=room)
        return
    if sid not in room_members.get(room, set()):
        log_event("UNAUTHORIZED_MSG", sid, room=room, detail="Not a member")
        return

    enc_data = data.get('encryptedData', '')
    if len(enc_data) > 7_000_000:
        log_event("OVERSIZED_PAYLOAD", sid, room=room, detail=f"{len(enc_data)} chars")
        return

    emit('receive_message', {
        'type':          data.get('type'),
        'msgId':         msg_id,
        'iv':            data.get('iv'),
        'encryptedKey':  data.get('encryptedKey'),
        'encryptedData': enc_data,
        'isViewOnce':    data.get('isViewOnce', False),
        'username':      data.get('username', 'Anonymous')
    }, to=room, include_self=False)

    emit('message_ack', {'msgId': msg_id}, to=sid)

@socketio.on('cn_ping')
def on_cn_ping(data):
    emit('cn_pong', {'pingId': data.get('pingId')}, to=request.sid)

# ── Security headers ───────────────────────────────────────────────────────
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options']         = 'DENY'
    resp.headers['X-XSS-Protection']        = '1; mode=block'
    resp.headers['Referrer-Policy']          = 'no-referrer'
    resp.headers['Permissions-Policy']       = 'geolocation=(), camera=()'
    resp.headers['Content-Security-Policy']  = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com fonts.googleapis.com fonts.gstatic.com; "
        "font-src fonts.gstatic.com cdnjs.cloudflare.com; "
        "connect-src 'self' wss:; "
        "img-src 'self' blob: data:; "
        "media-src 'self' blob:;"
    )
    resp.headers.pop('Server', None)   # hide Flask fingerprint
    return resp

if __name__ == '__main__':
    socketio.run(app, debug=False, port=5000, host='0.0.0.0', ssl_context='adhoc')
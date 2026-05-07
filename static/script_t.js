const socket = io();
let room = null;
let myKeyPair = null;
let peerPublicKey = null;
let mediaRecorder = null;
let audioChunks = [];
let currentRecordingModeViewOnce = false;
let myUsername = "Anonymous";
let peerUsername = "Unknown";

// ── CN Panel state ──
let msgIdCounter = 0;
// pingMap: msgId -> { t0: performance.now() at send, type }
// RTT is measured locally: sender emits ping timestamp, server echoes msgId back,
// sender computes elapsed. NO cross-device clock comparison.
let pingMap = {};
let handshakeStart = null;  // performance.now() — local only
let hsTimings = {};

// ── Bandwidth tracker state ──
let bwTxTotal = 0, bwRxTotal = 0;
let bwTxThisSec = 0, bwRxThisSec = 0;
const BW_HISTORY_LEN = 30;
let bwHistory = Array.from({length: BW_HISTORY_LEN}, () => ({ tx: 0, rx: 0 }));

// ── Message delivery map: msgId -> status DOM element ──
let msgStatusMap = {};

// ════════════════════════════════════════════
// SECURITY ENFORCERS
// ════════════════════════════════════════════
// ── Input sanitisation (client-side) ──
// Note: real security is enforced server-side.
// We sanitise here to give users immediate feedback only.
function sanitiseInput(str) {
    return str.replace(/[<>"';()]/g, '');
}

// ════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════
window.onload = function () {
    const params = new URLSearchParams(window.location.search);
    const urlRoom = params.get('room');
    if (urlRoom) document.getElementById('room-id').value = urlRoom;

    document.getElementById('btn-create').addEventListener('click', generateRoom);
    document.getElementById('btn-join').addEventListener('click', joinChat);
    document.getElementById('btn-copy').addEventListener('click', copyId);
    document.getElementById('toggle-cn-panel').addEventListener('click', () => {
        document.getElementById('cn-panel').classList.toggle('hidden');
    });
    document.getElementById('room-id').addEventListener('keyup', e => { if (e.key === 'Enter') joinChat(); });
    document.getElementById('username-input').addEventListener('keyup', e => { if (e.key === 'Enter') document.getElementById('room-id').focus(); });
    document.getElementById('message-input').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); sendTextMessage(); } });
};

function generateRoom() {
    const id = Array.from(window.crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('room-id').value = id;
    document.getElementById('share-link-text').innerText = id;
    document.getElementById('share-area').classList.remove('hidden');
}

async function joinChat() {
    room = document.getElementById('room-id').value.trim();
    const nameInput = document.getElementById('username-input').value.trim();
    myUsername = nameInput.length > 0 ? nameInput : "Anonymous";
    if (!room) return alert("ACCESS DENIED: Room ID Required");

    // Handshake telemetry — ALL measured with performance.now() locally
    handshakeStart = performance.now();
    hsTimings = { start: 0 };  // TCP/WS step: 0ms by definition (we just connected)
    updateHandshakeTimeline();

    document.getElementById('display-username').innerText = myUsername.toUpperCase();

    try {
        // Measure RSA keygen time locally — no network involved, this is accurate
        const rsaStart = performance.now();
        myKeyPair = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["encrypt", "decrypt"]
        );
        hsTimings.rsa_keygen = Math.round(performance.now() - rsaStart);
        updateHandshakeTimeline();

        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('chat-screen').classList.remove('hidden');
        document.getElementById('display-room').innerText = room;

        socket.emit('join', { room, username: myUsername });
    } catch (e) {
        console.error(e);
        alert("CRYPTO ERROR: Browser incompatible");
    }
}

// ════════════════════════════════════════════
// SIGNALING & KEY EXCHANGE
// ════════════════════════════════════════════
socket.on('user_joined', async (data) => {
    peerUsername = data.username || "Unknown";
    document.getElementById('status-text').innerHTML = `<span style='color:#bc13fe'>DETECTED: ${peerUsername}</span>`;
    const exportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
    socket.emit('signal_public_key', { room, key: exportedKey, request_reply: true, username: myUsername });
});

socket.on('receive_public_key', async (data) => {
    if (data.username) peerUsername = data.username;

    // Measure key import time locally — this is the real "session established" crypto cost
    const importStart = performance.now();
    peerPublicKey = await window.crypto.subtle.importKey("jwk", data.key, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
    hsTimings.aes_session = Math.round(performance.now() - importStart);
    updateHandshakeTimeline();

    document.getElementById('status-text').innerHTML = `<span style='color:#00f3ff'>SECURE UPLINK: ${peerUsername}</span>`;
    document.getElementById('connection-dot').classList.add('active');

    if (data.request_reply) {
        const myExportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
        socket.emit('signal_public_key', { room, key: myExportedKey, request_reply: false, username: myUsername });
    }

    // Start ping loop once peer is connected
    startPingLoop();
});

// ════════════════════════════════════════════
// RTT PING/PONG — local-only timing, no clock skew
// The sender records performance.now() before emit.
// Server echoes the msgId back immediately.
// Sender computes elapsed on receipt. Accurate to <1ms.
// ════════════════════════════════════════════
let pingInterval = null;

function startPingLoop() {
    if (pingInterval) return;
    // Send one ping now, then every 8 seconds
    sendPing();
    pingInterval = setInterval(sendPing, 8000);
}

function sendPing() {
    if (!peerPublicKey) return;
    const pingId = 'ping_' + (++msgIdCounter);
    const t0 = performance.now();
    pingMap[pingId] = { t0, type: 'ping' };
    socket.emit('cn_ping', { room, pingId });
}

socket.on('cn_pong', (data) => {
    const rec = pingMap[data.pingId];
    if (!rec) return;
    const rtt = Math.round(performance.now() - rec.t0);
    delete pingMap[data.pingId];
    logRtt('LINK', rtt);
});

// ════════════════════════════════════════════
// ENCRYPTION & SEND
// ════════════════════════════════════════════
async function encryptAndSend(dataBuffer, type, isViewOnce = false) {
    if (!peerPublicKey) return alert("UPLINK OFFLINE: Wait for peer.");
    try {
        const msgId = ++msgIdCounter;
        const t0 = performance.now();
        pingMap['msg_' + msgId] = { t0, type };

        const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, dataBuffer);
        const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
        const encryptedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, peerPublicKey, rawAesKey);

        const payload = {
            room, type, msgId,
            iv: ab2b64(iv),
            encryptedKey: ab2b64(encryptedKey),
            encryptedData: ab2b64(encryptedData),
            isViewOnce, username: myUsername
        };

        // Track TX bytes (approximate: encrypted payload size)
        const txBytes = payload.encryptedData.length + payload.encryptedKey.length + payload.iv.length;
        trackBandwidth('tx', txBytes);

        logPacket('OUT', payload.iv, payload.encryptedData);
        socket.emit('encrypted_message', payload);

        const msg = isViewOnce && (type === 'image' || type === 'audio') ? `SENT SELF-DESTRUCTING ${type.toUpperCase()}` : null;
        renderMessage(dataBuffer, type, 'sent', msg, isViewOnce, myUsername, msgId);
    } catch (err) { console.error("Encryption Error:", err); }
}

// Server echoes msgId so sender can compute RTT without cross-device clocks
socket.on('message_ack', (data) => {
    const key = 'msg_' + data.msgId;
    const rec = pingMap[key];
    if (!rec) return;
    const rtt = Math.round(performance.now() - rec.t0);
    delete pingMap[key];
    logRtt(rec.type, rtt);

    // Update delivery status to "delivered"
    const statusEl = msgStatusMap[data.msgId];
    if (statusEl) {
        statusEl.innerHTML = '<span class="tick tick-anim" style="color:var(--neon-green)">✓</span><span class="tick tick-anim" style="color:var(--neon-green);margin-left:-3px">✓</span>';
        statusEl.className = 'msg-status delivered';
        delete msgStatusMap[data.msgId];
    }
});

socket.on('receive_message', async (data) => {
    try {
        logPacket('IN', data.iv, data.encryptedData);

        // Track RX bytes
        const rxBytes = (data.encryptedData ? data.encryptedData.length : 0)
                      + (data.encryptedKey  ? data.encryptedKey.length  : 0)
                      + (data.iv            ? data.iv.length            : 0);
        trackBandwidth('rx', rxBytes);

        const iv = b642ab(data.iv);
        const encKey = b642ab(data.encryptedKey);
        const encData = b642ab(data.encryptedData);

        const rawAesKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, myKeyPair.privateKey, encKey);
        const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const decryptedData = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encData);

        renderMessage(decryptedData, data.type, 'received', null, data.isViewOnce, data.username);
    } catch (e) { console.error("Decryption Error:", e); }
});

// ════════════════════════════════════════════
// CN PANEL HELPERS
// ════════════════════════════════════════════
function logPacket(dir, iv, data) {
    const list = document.getElementById('pkt-list');
    // Remove placeholder
    const placeholder = list.querySelector('[data-placeholder]');
    if (placeholder) placeholder.remove();

    const now = new Date();
    const ts = now.toTimeString().slice(0, 8) + '.' + String(now.getMilliseconds()).padStart(3, '0');
    const dirClass = dir === 'OUT' ? 'out' : 'in';

    const row = document.createElement('div');
    row.className = 'pkt-row pkt-collapsible';
    row.dataset.expanded = 'false';
    row.innerHTML = `
        <div class="pkt-top">
            <span class="pkt-badge ${dirClass}">${dir}</span>
            <span class="pkt-ts">${ts}</span>
            <span class="pkt-expand-icon">▾</span>
        </div>
        <div class="pkt-hex pkt-preview">
            <span class="pk">iv:</span><span class="pv"> ${iv.substring(0, 13)}\u2026</span>
            \u2009<span class="pk">dat:</span><span class="pv"> ${data.substring(0, 12)}\u2026</span>
        </div>
        <div class="pkt-hex pkt-full" style="display:none;">
            <div><span class="pk">iv:\u00a0</span><span class="pv pkt-wrap">${iv}</span></div>
            <div style="margin-top:3px;"><span class="pk">dat:</span><span class="pv pkt-wrap">${data}</span></div>
            <div style="margin-top:3px;"><span class="pk">len:</span><span class="pv"> ${data.length} chars</span></div>
        </div>`;

    row.addEventListener('click', () => {
        const expanded = row.dataset.expanded === 'true';
        row.dataset.expanded = expanded ? 'false' : 'true';
        row.querySelector('.pkt-preview').style.display = expanded ? '' : 'none';
        row.querySelector('.pkt-full').style.display = expanded ? 'none' : '';
        row.querySelector('.pkt-expand-icon').style.transform = expanded ? '' : 'rotate(180deg)';
        row.style.background = expanded ? '' : 'rgba(0,243,255,0.03)';
    });

    list.prepend(row);
    if (list.children.length > 12) list.lastChild.remove();
}

function logRtt(type, ms) {
    const list = document.getElementById('rtt-list');
    // Remove placeholder
    const placeholder = list.querySelector('[data-placeholder]');
    if (placeholder) placeholder.remove();

    // Color thresholds
    const color = ms < 60 ? 'var(--neon-green)' : ms < 150 ? 'var(--neon-amber)' : 'var(--neon-red)';
    // Bar width: max 44px at 300ms
    const barW = Math.min(44, Math.max(2, Math.round((ms / 300) * 44)));

    const row = document.createElement('div');
    row.className = 'rtt-row';
    row.innerHTML = `
        <span class="rtt-arr">›</span>
        <span class="rtt-lbl">${type.toUpperCase()}</span>
        <div class="rtt-bar-wrap"><div class="rtt-bar-in" style="width:${barW}px;background:${color};"></div></div>
        <span class="rtt-num" style="color:${color};">${ms}ms</span>`;
    list.prepend(row);
    if (list.children.length > 8) list.lastChild.remove();
}

function updateHandshakeTimeline() {
    const steps = [
        { key: 'start',       label: 'TCP/WS Uplink',       desc: 'Socket connected' },
        { key: 'rsa_keygen',  label: 'RSA-2048 Generation',  desc: 'Local crypto keygen' },
        { key: 'aes_session', label: 'Key Import / Ready',   desc: 'Peer key imported' }
    ];
    const container = document.getElementById('hs-steps');
    container.innerHTML = steps.map((s, i) => {
        const done = hsTimings[s.key] !== undefined;
        const ms = done ? hsTimings[s.key] : null;
        return `
        <div class="hs-row ${done ? 'done' : 'wait'}">
            <div class="hs-circle ${done ? 'done' : 'wait'}">${done ? '✓' : i + 1}</div>
            <div class="hs-label ${done ? 'done' : 'wait'}">${s.label}</div>
            <div class="hs-ms ${done ? 'done' : 'wait'}">${ms !== null ? ms + 'ms' : '—'}</div>
        </div>`;
    }).join('');
}

// ════════════════════════════════════════════
// BANDWIDTH TRACKER
// ════════════════════════════════════════════
function fmtBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
    return (b / (1024 * 1024)).toFixed(2) + ' MB';
}

function trackBandwidth(dir, bytes) {
    if (dir === 'tx') { bwTxTotal += bytes; bwTxThisSec += bytes; }
    else              { bwRxTotal += bytes; bwRxThisSec += bytes; }
    // Update totals immediately
    const txEl = document.getElementById('bw-tx-val');
    const rxEl = document.getElementById('bw-rx-val');
    if (txEl) txEl.textContent = fmtBytes(bwTxTotal);
    if (rxEl) rxEl.textContent = fmtBytes(bwRxTotal);
}

// Every second: snapshot rates, push to history, redraw sparkline
setInterval(() => {
    const txRate = bwTxThisSec;
    const rxRate = bwRxThisSec;
    bwTxThisSec = 0;
    bwRxThisSec = 0;

    bwHistory.push({ tx: txRate, rx: rxRate });
    if (bwHistory.length > BW_HISTORY_LEN) bwHistory.shift();

    const txRateEl = document.getElementById('bw-tx-rate');
    const rxRateEl = document.getElementById('bw-rx-rate');
    if (txRateEl) txRateEl.textContent = fmtBytes(txRate) + '/s';
    if (rxRateEl) rxRateEl.textContent = fmtBytes(rxRate) + '/s';

    drawSparkline();
}, 1000);

function drawSparkline() {
    const canvas = document.getElementById('bw-sparkline');
    if (!canvas) return;
    const wrap = canvas.parentElement;
    const W = wrap.clientWidth || 240;
    const H = 36;
    canvas.width  = W;
    canvas.height = H;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, W, H);

    const maxVal = Math.max(1, ...bwHistory.map(p => Math.max(p.tx, p.rx)));
    const stepX = W / (BW_HISTORY_LEN - 1);

    const drawLine = (key, color) => {
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.2;
        ctx.shadowBlur = 4;
        ctx.shadowColor = color;
        bwHistory.forEach((p, i) => {
            const x = i * stepX;
            const y = H - 2 - ((p[key] / maxVal) * (H - 6));
            i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Fill under line
        ctx.globalAlpha = 0.07;
        ctx.fillStyle = color;
        ctx.lineTo((bwHistory.length - 1) * stepX, H);
        ctx.lineTo(0, H);
        ctx.fill();
        ctx.globalAlpha = 1;
        ctx.shadowBlur = 0;
    };

    drawLine('rx', '#bc13fe');
    drawLine('tx', '#00f3ff');
}

// ════════════════════════════════════════════
// UI & MEDIA
// ════════════════════════════════════════════
function sendTextMessage() {
    const input = document.getElementById('message-input');
    if (input.value.trim()) {
        encryptAndSend(new TextEncoder().encode(input.value), 'text');
        input.value = '';
        input.focus();
    }
}

function triggerImageUpload(isViewOnce) {
    const fileInput = document.getElementById('image-input');
    fileInput.value = '';
    fileInput.onchange = function () {
        const file = fileInput.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (evt) => encryptAndSend(evt.target.result, 'image', isViewOnce);
            reader.readAsArrayBuffer(file);
        }
    };
    fileInput.click();
}

async function startRecording(isViewOnce) {
    currentRecordingModeViewOnce = isViewOnce;
    const btn = document.getElementById('record-btn');
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        audioChunks = [];
        mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
        mediaRecorder.onstop = async () => {
            const blob = new Blob(audioChunks, { type: 'audio/webm' });
            encryptAndSend(await blob.arrayBuffer(), 'audio', currentRecordingModeViewOnce);
            btn.classList.remove('recording');
            stream.getTracks().forEach(t => t.stop());
        };
        mediaRecorder.start();
        btn.classList.add('recording');
    } catch (e) { console.error(e); alert("AUDIO HARDWARE BLOCKED"); }
}

function stopRecording() {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
}

// ── Custom Audio Player ──
function buildAudioPlayer(url, source) {
    const isSent = source === 'sent';
    const btnClass = isSent ? 'sent-ap' : 'recv-ap';
    const fillClass = isSent ? 'sent-fill' : 'recv-fill';

    const wrap = document.createElement('div');
    wrap.className = 'audio-player';

    const audio = document.createElement('audio');
    audio.className = 'raw-audio';
    audio.src = url;
    audio.controlsList = 'nodownload';

    const btn = document.createElement('button');
    btn.className = `ap-btn ${btnClass}`;
    btn.innerHTML = '<i class="fas fa-play"></i>';

    const info = document.createElement('div');
    info.className = 'ap-info';

    const track = document.createElement('div');
    track.className = 'ap-track';
    const fill = document.createElement('div');
    fill.className = `ap-fill ${fillClass}`;
    track.appendChild(fill);

    const timeEl = document.createElement('div');
    timeEl.className = 'ap-time';
    timeEl.innerText = '0:00 / 0:00';

    info.appendChild(track);
    info.appendChild(timeEl);

    wrap.appendChild(btn);
    wrap.appendChild(info);
    wrap.appendChild(audio);

    const fmt = (s) => {
        const m = Math.floor(s / 60);
        const sec = Math.floor(s % 60);
        return `${m}:${String(sec).padStart(2, '0')}`;
    };

    btn.onclick = () => {
        if (audio.paused) { audio.play(); btn.innerHTML = '<i class="fas fa-pause"></i>'; }
        else { audio.pause(); btn.innerHTML = '<i class="fas fa-play"></i>'; }
    };
    audio.ontimeupdate = () => {
        const pct = audio.duration ? (audio.currentTime / audio.duration) * 100 : 0;
        fill.style.width = pct + '%';
        timeEl.innerText = `${fmt(audio.currentTime)} / ${fmt(audio.duration || 0)}`;
    };
    audio.onended = () => { btn.innerHTML = '<i class="fas fa-play"></i>'; fill.style.width = '0%'; };
    track.onclick = (e) => {
        if (!audio.duration) return;
        const rect = track.getBoundingClientRect();
        audio.currentTime = ((e.clientX - rect.left) / rect.width) * audio.duration;
    };

    return wrap;
}

function renderMessage(buffer, type, source, customText = null, isViewOnce = false, senderName = "Anonymous", msgId = null) {
    const div = document.createElement('div');
    div.className = `message ${source}`;

    const nameLabel = document.createElement('div');
    nameLabel.className = 'sender-name';
    nameLabel.innerText = senderName;
    div.appendChild(nameLabel);

    if (customText) {
        const info = document.createElement('span');
        info.innerHTML = `<i class="fas fa-info-circle"></i> ${customText}`;
        info.style.cssText = 'font-family:var(--font-code);font-size:0.75rem;';
        div.appendChild(info);
    } else if (type === 'text') {
        const txt = document.createElement('span');
        txt.innerText = new TextDecoder().decode(buffer);
        div.appendChild(txt);
    } else if (type === 'image') {
        const blob = new Blob([buffer]);
        const url = URL.createObjectURL(blob);
        if (isViewOnce && source === 'received') {
            const vc = document.createElement('div');
            vc.className = 'vo-container';
            vc.innerHTML = `<div style="font-size:0.85rem;color:var(--neon-red);margin-bottom:4px;">HIDDEN DATA</div>
                            <button class="vo-btn">REVEAL (10s)</button>`;
            vc.querySelector('button').onclick = function () {
                openModal(url);
                div.innerHTML = `<span class="sender-name">${senderName}</span><span style="color:var(--neon-blue);font-family:var(--font-code);font-size:0.75rem;">[ VIEWING DATA... ]</span>`;
                startDestructTimer(div, url, "[ IMAGE SCRUBBED ]", true);
            };
            div.appendChild(vc);
        } else {
            const mc = document.createElement('div');
            mc.className = 'media-content';
            const img = document.createElement('img');
            img.src = url;
            img.onclick = () => openModal(url);
            mc.appendChild(img);
            div.appendChild(mc);
        }
    } else if (type === 'audio') {
        const blob = new Blob([buffer]);
        const url = URL.createObjectURL(blob);
        if (isViewOnce && source === 'received') {
            const vc = document.createElement('div');
            vc.className = 'vo-container';
            vc.innerHTML = `<div style="font-size:0.85rem;color:var(--neon-red);margin-bottom:4px;">AUDIO LOG</div>
                            <button class="vo-btn">PLAY</button>`;
            vc.querySelector('button').onclick = function () {
                div.innerHTML = `<span class="sender-name">${senderName}</span>`;
                const player = buildAudioPlayer(url, source);
                div.appendChild(player);
                player.querySelector('.raw-audio').play();
                player.querySelector('.raw-audio').onended = () => startDestructTimer(div, url, "[ AUDIO SCRUBBED ]");
            };
            div.appendChild(vc);
        } else {
            div.appendChild(buildAudioPlayer(url, source));
        }
    }

    // ── Delivery status for sent messages ──
    if (source === 'sent' && msgId !== null) {
        const statusEl = document.createElement('div');
        statusEl.className = 'msg-status sending';
        statusEl.innerHTML = '<span class="tick">✓</span>';
        div.appendChild(statusEl);
        // "Sent" state: single grey tick immediately
        setTimeout(() => {
            statusEl.innerHTML = '<span class="tick tick-anim">✓</span>';
            statusEl.className = 'msg-status sent';
        }, 80);
        // Register for "delivered" upgrade when ack arrives
        msgStatusMap[msgId] = statusEl;
    }

    document.getElementById('messages').appendChild(div);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

function startDestructTimer(div, url, msg, closeModal_ = false) {
    setTimeout(() => {
        div.innerHTML = `<span style="color:#444;font-family:var(--font-code);font-size:0.7rem;">${msg}</span>`;
        if (url) URL.revokeObjectURL(url);
        if (closeModal_) closeModal();
    }, 10000);
}

function openModal(src) {
    document.getElementById('image-modal').classList.add('modal-active');
    document.getElementById('full-image').src = src;
}
function closeModal() {
    document.getElementById('image-modal').classList.remove('modal-active');
    setTimeout(() => { document.getElementById('full-image').src = ''; }, 300);
}
function copyId() {
    const text = document.getElementById('share-link-text').innerText;
    if (text) { navigator.clipboard.writeText(text); alert("ACCESS CODE COPIED"); }
}

// ── Utils ──
function ab2b64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i += 8192)
        binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, bytes.byteLength)));
    return window.btoa(binary);
}
function b642ab(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}



// ════════════════════════════════════════════
// SECURITY MONITOR
// ════════════════════════════════════════════

// ── Live security event feed from server ──
socket.on('security_event', (data) => {
    const log = document.getElementById('sec-event-log');
    if (!log) return;

    const placeholder = log.querySelector('[data-placeholder]');
    if (placeholder) placeholder.remove();

    const typeClass = data.type.replace(/[^A-Z_]/g, '');
    const row = document.createElement('div');
    row.className = 'sev-row';
    row.innerHTML = `
        <span class="sev-ts">${data.ts}</span>
        <span class="sev-type ${typeClass}">${data.type}</span>
        <span class="sev-detail">${data.sid} ${data.room !== '–' ? '· ' + data.room : ''} ${data.detail ? '· ' + data.detail : ''}</span>`;
    log.prepend(row);
    if (log.children.length > 20) log.lastChild.remove();

    // Flash the CN panel toggle button if a threat is detected
    const threatTypes = ['RATE_LIMIT','BLOCKED','INVALID_ROOM','INVALID_USERNAME','UNAUTHORIZED_MSG','OVERSIZED_PAYLOAD'];
    if (threatTypes.includes(data.type)) {
        const btn = document.getElementById('toggle-cn-panel');
        if (btn) {
            btn.style.borderColor = 'var(--neon-red)';
            btn.style.color = 'var(--neon-red)';
            setTimeout(() => { btn.style.borderColor = ''; btn.style.color = ''; }, 2000);
        }
    }
});

// ── Vulnerability Scanner ──
async function runVulnScan() {
    const btn = document.getElementById('scan-btn');
    const result = document.getElementById('sec-scan-result');
    if (!btn || !result) return;

    btn.disabled = true;
    btn.textContent = 'SCANNING...';
    result.innerHTML = '<div style="font-family:var(--font-code);font-size:0.46rem;color:rgba(0,255,136,0.4);text-align:center;padding:10px 0;letter-spacing:2px;">RUNNING CHECKS...</div>';

    try {
        const resp = await fetch('/api/vulnerability-scan');
        const data = await resp.json();

        const scoreColor = data.score >= 90 ? 'var(--neon-green)'
                         : data.score >= 75 ? '#7fff00'
                         : data.score >= 60 ? 'var(--neon-amber)'
                         : data.score >= 40 ? '#ff8c00'
                         : 'var(--neon-red)';

        const barColor = scoreColor;
        const findings = data.findings || [];

        // Count severities
        const counts = {PASS:0, INFO:0, MEDIUM:0, HIGH:0, CRITICAL:0};
        findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

        let html = `
        <div class="sec-score-ring">
            <div class="sec-grade ${data.grade}" style="color:${scoreColor};">${data.grade}</div>
            <div class="sec-score-detail">
                <div style="font-family:var(--font-code);font-size:0.52rem;color:rgba(255,255,255,0.5);">Score: <span style="color:${scoreColor};font-weight:700;">${data.score}/100</span></div>
                <div class="sec-score-bar-wrap"><div class="sec-score-bar" style="width:${data.score}%;background:${barColor};"></div></div>
                <div style="font-family:var(--font-code);font-size:0.38rem;color:#252530;margin-top:3px;">${data.scanned_at}</div>
            </div>
        </div>
        <div style="display:flex;gap:4px;margin-bottom:6px;flex-wrap:wrap;">
            ${counts.CRITICAL > 0 ? `<span class="sec-badge CRITICAL">${counts.CRITICAL} CRITICAL</span>` : ''}
            ${counts.HIGH     > 0 ? `<span class="sec-badge HIGH">${counts.HIGH} HIGH</span>` : ''}
            ${counts.MEDIUM   > 0 ? `<span class="sec-badge MEDIUM">${counts.MEDIUM} MEDIUM</span>` : ''}
            ${counts.INFO     > 0 ? `<span class="sec-badge INFO">${counts.INFO} INFO</span>` : ''}
            ${counts.PASS     > 0 ? `<span class="sec-badge PASS">${counts.PASS} PASS</span>` : ''}
        </div>`;

        // Show critical/high/medium first, then pass
        const order = ['CRITICAL','HIGH','MEDIUM','INFO','PASS'];
        const sorted = [...findings].sort((a,b) => order.indexOf(a.severity) - order.indexOf(b.severity));

        sorted.forEach(f => {
            html += `
            <div class="sec-finding ${f.severity}">
                <div class="sec-finding-hdr">
                    <span class="sec-badge ${f.severity}">${f.severity}</span>
                    <span class="sec-title">${f.id} — ${f.title}</span>
                </div>
                <div class="sec-detail">${f.detail}</div>
                ${f.fix ? `<div class="sec-fix">Fix: ${f.fix}</div>` : ''}
            </div>`;
        });

        result.innerHTML = html;
    } catch (err) {
        result.innerHTML = `<div style="font-family:var(--font-code);font-size:0.46rem;color:var(--neon-red);padding:6px;">SCAN FAILED: ${err.message}</div>`;
    }

    btn.disabled = false;
    btn.textContent = '⬡ RUN VULNERABILITY SCAN';
}

window.runVulnScan = runVulnScan;

// Global exports
window.generateRoom = generateRoom; window.joinChat = joinChat; window.copyId = copyId;
window.triggerImageUpload = triggerImageUpload; window.startRecording = startRecording;
window.stopRecording = stopRecording; window.sendTextMessage = sendTextMessage;
window.closeModal = closeModal; window.openModal = openModal;
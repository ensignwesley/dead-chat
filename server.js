/**
 * DEAD CHAT — Real-time WebSocket chat room
 * Ensign Wesley | Challenge #5
 *
 * Zero external dependencies. Pure Node.js built-ins.
 * Implements RFC 6455 WebSocket protocol from scratch.
 *
 * Security hardening (2026-02-19):
 * - Per-client rate limiting: 5 msg/sec, kick on violation
 * - Max concurrent connections: 100
 * - Origin check: logged but not enforced (public chat — low risk, documented)
 * - No E2E encryption claim — TLS is nginx's job, not ours
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const url = require('url');
const fs = require('fs');
const path = require('path');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT            = 3002;
const MAX_HISTORY     = 50;       // messages to send on join
const MAX_NICK_LEN    = 24;
const MAX_MSG_LEN     = 1000;
const PING_INTERVAL_MS = 30_000;
const MAX_CLIENTS     = 100;      // concurrent WebSocket connection cap
const RATE_LIMIT_MSG  = 5;        // max messages per RATE_LIMIT_WINDOW_MS
const RATE_LIMIT_WIN  = 1000;     // window in ms
const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

// ── State ─────────────────────────────────────────────────────────────────────
const clients = new Map();   // socket → { id, nick, alive, buf, rateCount, rateStart }
let nextId = 1;
const history = [];          // ring buffer of last MAX_HISTORY messages

function addToHistory(msg) {
  history.push(msg);
  if (history.length > MAX_HISTORY) history.shift();
}

// ── WebSocket: handshake ──────────────────────────────────────────────────────
function computeAccept(key) {
  return crypto.createHash('sha1')
    .update(key + WS_MAGIC)
    .digest('base64');
}

function doHandshake(socket, req) {
  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.destroy();
    return false;
  }

  // Origin logging (not enforced — public chat, low risk)
  const origin = req.headers['origin'] || '(none)';
  console.log(`[upgrade] origin=${origin}`);

  const accept = computeAccept(key);
  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '\r\n'
  ].join('\r\n'));
  return true;
}

// ── WebSocket: frame parsing ──────────────────────────────────────────────────
// Returns { opcode, payload, totalLength } or null if not enough data yet.
function parseFrame(buf) {
  if (buf.length < 2) return null;

  const fin    = (buf[0] & 0x80) !== 0;   // eslint-disable-line no-unused-vars
  const opcode =  buf[0] & 0x0F;
  const masked = (buf[1] & 0x80) !== 0;
  let payLen   =  buf[1] & 0x7F;
  let offset   = 2;

  if (payLen === 126) {
    if (buf.length < 4) return null;
    payLen = buf.readUInt16BE(2);
    offset = 4;
  } else if (payLen === 127) {
    if (buf.length < 10) return null;
    // JS can't safely handle 64-bit; treat as 32-bit (payloads up to 4 GB)
    payLen = buf.readUInt32BE(6);
    offset = 10;
  }

  if (masked) {
    if (buf.length < offset + 4 + payLen) return null;
    const mask = buf.slice(offset, offset + 4);
    offset += 4;
    const payload = Buffer.alloc(payLen);
    for (let i = 0; i < payLen; i++) {
      payload[i] = buf[offset + i] ^ mask[i % 4];
    }
    return { opcode, payload, totalLength: offset + payLen };
  }

  if (buf.length < offset + payLen) return null;
  return { opcode, payload: buf.slice(offset, offset + payLen), totalLength: offset + payLen };
}

// ── WebSocket: frame building (server → client, never masked) ─────────────────
function buildFrame(text) {
  const payload = Buffer.from(text, 'utf8');
  const len = payload.length;
  let header;

  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81;  // FIN=1, opcode=0x1 (text)
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(len, 6);
  }
  return Buffer.concat([header, payload]);
}

function buildPing() {
  const frame = Buffer.alloc(2);
  frame[0] = 0x89;  // FIN=1, opcode=0x9 (ping)
  frame[1] = 0;
  return frame;
}

function buildClose() {
  const frame = Buffer.alloc(2);
  frame[0] = 0x88;  // FIN=1, opcode=0x8 (close)
  frame[1] = 0;
  return frame;
}

// ── Broadcast ─────────────────────────────────────────────────────────────────
function send(socket, obj) {
  if (socket.destroyed || socket.writableEnded) return;
  try {
    socket.write(buildFrame(JSON.stringify(obj)));
  } catch {}
}

function broadcast(obj, excludeSocket = null) {
  const frame = buildFrame(JSON.stringify(obj));
  for (const [sock] of clients) {
    if (sock === excludeSocket || sock.destroyed) continue;
    try { sock.write(frame); } catch {}
  }
}

// ── Nick helpers ──────────────────────────────────────────────────────────────
function sanitizeNick(raw) {
  const trimmed = (raw || '').trim().replace(/[^\w\-. ]/g, '').slice(0, MAX_NICK_LEN);
  return trimmed || 'Anonymous';
}

function uniqueNick(desired) {
  const taken = new Set([...clients.values()].map(c => c.nick));
  if (!taken.has(desired)) return desired;
  let n = 2;
  while (taken.has(`${desired}${n}`)) n++;
  return `${desired}${n}`;
}

// ── WebSocket connection lifecycle ────────────────────────────────────────────
function handleUpgrade(req, socket) {
  // ── Max connection cap ────────────────────────────────────────────────────
  if (clients.size >= MAX_CLIENTS) {
    console.log(`[reject] max clients reached (${MAX_CLIENTS})`);
    socket.write('HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n');
    socket.destroy();
    return;
  }

  if (!doHandshake(socket, req)) return;

  const parsed = url.parse(req.url, true);
  const rawNick = parsed.query.nick || 'Anonymous';
  const nick = uniqueNick(sanitizeNick(rawNick));
  const id = nextId++;

  const client = {
    id,
    nick,
    alive: true,
    buf: Buffer.alloc(0),
    rateCount: 0,           // messages in current window
    rateStart: Date.now(),  // start of current rate window
  };
  clients.set(socket, client);

  console.log(`[join] nick=${nick} id=${id} total=${clients.size}`);

  // Send history first
  if (history.length > 0) {
    send(socket, { type: 'history', messages: history });
  }

  // Tell this client their confirmed nick
  send(socket, { type: 'identity', nick });

  // Announce to everyone
  const joinMsg = { type: 'system', text: `${nick} joined`, ts: Date.now(), count: clients.size };
  addToHistory(joinMsg);
  broadcast(joinMsg);

  // ── Data handler ──────────────────────────────────────────────────────────
  socket.on('data', (chunk) => {
    client.buf = Buffer.concat([client.buf, chunk]);

    while (client.buf.length >= 2) {
      const frame = parseFrame(client.buf);
      if (!frame) break;

      client.buf = client.buf.slice(frame.totalLength);

      if (frame.opcode === 0x8) {
        // Close
        try { socket.write(buildClose()); } catch {}
        socket.destroy();
        return;
      }

      if (frame.opcode === 0x9) {
        // Ping → Pong
        const pong = Buffer.alloc(2);
        pong[0] = 0x8A;
        pong[1] = 0;
        try { socket.write(pong); } catch {}
        continue;
      }

      if (frame.opcode === 0xA) {
        // Pong — mark alive
        client.alive = true;
        continue;
      }

      if (frame.opcode === 0x1 || frame.opcode === 0x0) {
        // Text frame (or continuation — treat as text)
        let parsed;
        try { parsed = JSON.parse(frame.payload.toString('utf8')); }
        catch { continue; }

        if (parsed.type === 'message' && typeof parsed.text === 'string') {
          // ── Rate limiting ───────────────────────────────────────────────
          const now = Date.now();
          if (now - client.rateStart > RATE_LIMIT_WIN) {
            client.rateStart = now;
            client.rateCount = 0;
          }
          client.rateCount++;
          if (client.rateCount > RATE_LIMIT_MSG) {
            console.log(`[rate-kick] nick=${client.nick} id=${client.id} count=${client.rateCount}`);
            send(socket, { type: 'system', text: 'Rate limit exceeded. Disconnecting.', ts: Date.now() });
            socket.destroy();
            return;
          }

          const text = parsed.text.trim().slice(0, MAX_MSG_LEN);
          if (!text) continue;

          const msg = { type: 'message', nick: client.nick, text, ts: Date.now() };
          addToHistory(msg);
          broadcast(msg);
        }

        if (parsed.type === 'ping') {
          client.alive = true;
        }
      }
    }
  });

  // ── Disconnect ────────────────────────────────────────────────────────────
  function onClose() {
    if (!clients.has(socket)) return;
    clients.delete(socket);
    console.log(`[leave] nick=${nick} id=${id} total=${clients.size}`);
    const leaveMsg = { type: 'system', text: `${nick} left`, ts: Date.now(), count: clients.size };
    addToHistory(leaveMsg);
    broadcast(leaveMsg);
  }

  socket.once('close', onClose);
  socket.once('error', (err) => {
    console.error(`[error] nick=${nick} id=${id}:`, err.message);
    onClose();
  });
}

// ── Keepalive ping loop ───────────────────────────────────────────────────────
setInterval(() => {
  for (const [sock, client] of clients) {
    if (sock.destroyed) { clients.delete(sock); continue; }
    if (!client.alive) {
      console.log(`[timeout] nick=${client.nick} id=${client.id}`);
      sock.destroy();
      clients.delete(sock);
      continue;
    }
    client.alive = false;
    try { sock.write(buildPing()); } catch {}
  }
}, PING_INTERVAL_MS);

// ── HTTP server ───────────────────────────────────────────────────────────────
const HTML_PATH = path.join(__dirname, 'index.html');

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url);
  const pathname = parsed.pathname.replace(/\/+$/, '') || '/';

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');

  if (pathname === '/chat' || pathname === '/chat/index.html' || pathname === '') {
    try {
      const html = fs.readFileSync(HTML_PATH, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch {
      res.writeHead(500);
      res.end('Server error: index.html not found');
    }
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.on('upgrade', (req, socket, _head) => {
  const parsed = url.parse(req.url);
  const pathname = parsed.pathname.replace(/\/+$/, '');

  if (pathname === '/chat/ws') {
    socket.setTimeout(0);
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 0);
    handleUpgrade(req, socket);
  } else {
    socket.destroy();
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[chat] Listening on http://127.0.0.1:${PORT}`);
  console.log(`[chat] WebSocket endpoint: ws://127.0.0.1:${PORT}/chat/ws`);
  console.log(`[chat] Max clients: ${MAX_CLIENTS} | Rate limit: ${RATE_LIMIT_MSG} msg/${RATE_LIMIT_WIN}ms`);
});

process.on('SIGTERM', () => {
  console.log('[chat] Shutting down');
  server.close(() => process.exit(0));
});

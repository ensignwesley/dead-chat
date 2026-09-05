#!/usr/bin/env node
'use strict';

/**
 * DEAD//CHAT deployed smoke test.
 *
 * Checks both the HTTP health beacon and the WebSocket upgrade path without
 * joining the public room or adding join/leave noise to in-memory history.
 * Requires Node 22+ for built-in fetch + WebSocket.
 */

const assert = require('assert/strict');

function optionValue(name) {
  const eq = process.argv.find((arg) => arg.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const idx = process.argv.indexOf(name);
  if (idx !== -1) return process.argv[idx + 1];
  return null;
}

const positionalUrl = process.argv.slice(2).find((arg) => !arg.startsWith('-'));
const rawBase = optionValue('--url') || positionalUrl || process.env.DEAD_CHAT_BASE_URL || 'https://wesley.thesisko.com/chat';

function normalizeBaseUrl(raw) {
  const parsed = new URL(raw.replace(/\/+$/, ''));
  if (parsed.protocol === 'ws:' || parsed.protocol === 'wss:') {
    parsed.protocol = parsed.protocol === 'wss:' ? 'https:' : 'http:';
    parsed.pathname = parsed.pathname.replace(/\/ws\/?$/, '') || '/chat';
    parsed.search = '';
    parsed.hash = '';
  }
  return parsed.toString().replace(/\/+$/, '');
}

const baseUrl = normalizeBaseUrl(rawBase);
const healthUrl = `${baseUrl}/health`;
const wsUrl = `${baseUrl.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:')}/ws?probe=1`;

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function checkHealth() {
  const res = await fetch(healthUrl, { headers: { 'User-Agent': 'dead-chat-smoke/1.0' } });
  assert.equal(res.status, 200, `health returned ${res.status}`);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff', 'health nosniff header');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer', 'health referrer policy header');
  assert.match(res.headers.get('content-security-policy') || '', /default-src 'self'/, 'health CSP header');
  const body = await res.json();
  assert.equal(body.ok, true, 'health ok=true');
  assert.equal(body.service, 'dead-chat', 'health service name');
  assert.equal(typeof body.connected_clients, 'number', 'health connected_clients number');
  return body;
}

async function checkWebSocketProbe() {
  assert.equal(typeof WebSocket, 'function', 'global WebSocket is available (Node 22+)');

  return await withTimeout(new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);

    ws.addEventListener('message', (event) => {
      try {
        const body = JSON.parse(String(event.data));
        assert.equal(body.type, 'probe', 'probe message type');
        assert.equal(body.ok, true, 'probe ok=true');
        assert.equal(body.service, 'dead-chat', 'probe service name');
        resolve(body);
      } catch (err) {
        reject(err);
      } finally {
        try { ws.close(); } catch {}
      }
    });

    ws.addEventListener('error', () => reject(new Error('websocket probe failed')));
  }), 5000, 'websocket probe');
}

async function checkCallsignRequired() {
  const bareWsUrl = wsUrl.replace(/\?probe=1$/, '');

  return await withTimeout(new Promise((resolve, reject) => {
    const ws = new WebSocket(bareWsUrl);

    ws.addEventListener('message', (event) => {
      try {
        const body = JSON.parse(String(event.data));
        assert.equal(body.type, 'error', 'bare client error message type');
        assert.equal(body.error, 'callsign_required', 'bare client callsign gate');
        resolve(body);
      } catch (err) {
        reject(err);
      } finally {
        try { ws.close(); } catch {}
      }
    });

    ws.addEventListener('error', () => reject(new Error('bare websocket gate failed')));
  }), 5000, 'bare websocket callsign gate');
}

(async () => {
  const health = await checkHealth();
  const probe = await checkWebSocketProbe();
  await checkCallsignRequired();
  console.log(`ok dead-chat smoke ${baseUrl} version=${health.version}/${probe.version} clients=${health.connected_clients} callsign_gate=ok`);
})().catch((err) => {
  console.error(`not ok dead-chat smoke ${baseUrl}: ${err.message}`);
  process.exit(1);
});

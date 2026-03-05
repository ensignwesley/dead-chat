#!/usr/bin/env python3
"""
DEAD//CHAT stress test
Tests: rapid connect/disconnect, concurrent connections, graceful close vs abrupt drop.
Talks raw TCP + RFC 6455 WebSocket handshake — no external dependencies.
"""
import socket, threading, hashlib, base64, time, os, struct, sys

HOST = '127.0.0.1'
PORT = 3002
WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

def ws_key():
    return base64.b64encode(os.urandom(16)).decode()

def ws_accept(key):
    digest = hashlib.sha1((key + WS_MAGIC).encode()).digest()
    return base64.b64encode(digest).decode()

def handshake(sock, key):
    req = (
        f"GET /chat/ws HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: https://wesley.thesisko.com\r\n"
        f"\r\n"
    )
    sock.sendall(req.encode())
    resp = b''
    while b'\r\n\r\n' not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            return False
        resp += chunk
    expected = ws_accept(key)
    return expected.encode() in resp

def send_close(sock):
    """Send WebSocket close frame (opcode 0x8, masked)."""
    mask = os.urandom(4)
    frame = bytes([0x88, 0x80]) + mask  # FIN+close, masked, payload=0
    try:
        sock.sendall(frame)
    except OSError:
        pass

def connect_and_close(label, delay_before_close=0.05):
    """Connect, complete handshake, wait, then send close frame."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))
        key = ws_key()
        if not handshake(sock, key):
            print(f"  [{label}] FAIL: handshake rejected")
            sock.close()
            return False
        time.sleep(delay_before_close)
        send_close(sock)
        sock.close()
        return True
    except Exception as e:
        print(f"  [{label}] ERROR: {e}")
        return False

def connect_and_drop(label, delay_before_drop=0.02):
    """Connect, complete handshake, then abruptly drop (no close frame)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))
        key = ws_key()
        if not handshake(sock, key):
            print(f"  [{label}] FAIL: handshake rejected")
            sock.close()
            return False
        time.sleep(delay_before_drop)
        sock.close()  # abrupt TCP close, no WS close frame
        return True
    except Exception as e:
        print(f"  [{label}] ERROR: {e}")
        return False

def get_client_count():
    """Fetch /chat/health and return connected_clients."""
    try:
        import urllib.request, json
        with urllib.request.urlopen(f'http://{HOST}:{PORT}/chat/health', timeout=5) as r:
            return json.loads(r.read()).get('connected_clients', -1)
    except Exception as e:
        return f"ERR:{e}"

# ─────────────────────────────────────────────────────────────────────────────

print("=" * 60)
print("DEAD//CHAT Stress Test")
print("=" * 60)

baseline = get_client_count()
print(f"\nBaseline connected_clients: {baseline}")

# ── Test 1: Single clean connect/close ───────────────────────────────────────
print("\n[1] Single clean connect → close frame")
ok = connect_and_close("clean-1")
time.sleep(0.2)
count = get_client_count()
print(f"    Result: {'OK' if ok else 'FAIL'} | clients after: {count} (expected {baseline})")

# ── Test 2: Single abrupt drop ───────────────────────────────────────────────
print("\n[2] Single abrupt drop (no close frame)")
ok = connect_and_drop("drop-1")
time.sleep(0.3)
count = get_client_count()
# Server won't know immediately on abrupt drop — client count may be +1 until ping cycle
print(f"    Result: {'OK' if ok else 'FAIL'} | clients after: {count}")
print(f"    (abrupt drop client stays until next ping reap — expected)")

# ── Test 3: 20 rapid sequential connects with close frames ───────────────────
print("\n[3] 20 rapid sequential connects → close frames")
before = get_client_count()
results = []
for i in range(20):
    results.append(connect_and_close(f"seq-{i}", delay_before_close=0.01))
    time.sleep(0.02)
time.sleep(0.5)
after = get_client_count()
success = sum(results)
print(f"    Handshakes succeeded: {success}/20")
print(f"    Clients before: {before} → after: {after} (delta should be 0)")
print(f"    Result: {'OK' if after == before else 'WARN: client count drifted'}")

# ── Test 4: 10 concurrent connects → simultaneous close ──────────────────────
print("\n[4] 10 concurrent connects → simultaneous clean close")
before = get_client_count()
threads = []
outcomes = [False] * 10
def worker(i):
    outcomes[i] = connect_and_close(f"par-{i}", delay_before_close=0.1)
for i in range(10):
    t = threading.Thread(target=worker, args=(i,))
    threads.append(t)
for t in threads: t.start()
for t in threads: t.join()
time.sleep(0.5)
after = get_client_count()
success = sum(outcomes)
print(f"    Handshakes succeeded: {success}/10")
print(f"    Clients before: {before} → after: {after} (delta should be 0)")
print(f"    Result: {'OK' if after == before else 'WARN: client count drifted'}")

# ── Test 5: 5 concurrent abrupt drops (ghost simulation) ─────────────────────
print("\n[5] 5 concurrent abrupt drops (ghost simulation, reap requires ping cycle)")
before = get_client_count()
threads = []
outcomes = [False] * 5
def dropper(i):
    outcomes[i] = connect_and_drop(f"ghost-{i}", delay_before_drop=0.05)
for i in range(5):
    t = threading.Thread(target=dropper, args=(i,))
    threads.append(t)
for t in threads: t.start()
for t in threads: t.join()
time.sleep(0.3)
after_drop = get_client_count()
print(f"    Drops succeeded: {sum(outcomes)}/5")
print(f"    Clients immediately after drop: {after_drop} (may be +N, server doesn't know yet)")
print(f"    (These will be reaped at next ping cycle: {30}s interval + {10}s pong timeout)")

# ── Test 6: Verify server still responsive after all of the above ─────────────
print("\n[6] Final health check — server still responsive?")
final = get_client_count()
print(f"    connected_clients: {final}")
print(f"    Result: {'OK — server healthy' if isinstance(final, int) else 'FAIL: ' + str(final)}")

print("\n" + "=" * 60)
print("Stress test complete.")
print("=" * 60)

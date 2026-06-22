#!/usr/bin/env bash
set -euo pipefail

# Non-destructive Linux network-namespace smoke test for Trustfall.
# Creates isolated namespaces: gw, target, mole on an isolated bridge.
# Requires: root, iproute2, iptables, python3, openssl, and Python deps
# cryptography+scapy installed either system-wide or in the active environment.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BR="trustfall-br0"
GW_NS="trustfall-gw"
TARGET_NS="trustfall-target"
MOLE_NS="trustfall-ns"
NET="10.13.37"
SESSION="${ROOT}/lab/session-$(date +%s)"
PIDS=()

cleanup() {
  set +e
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  ip netns pids "$GW_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns pids "$TARGET_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns pids "$MOLE_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip link del "$BR" 2>/dev/null || true
  ip netns del "$GW_NS" 2>/dev/null || true
  ip netns del "$TARGET_NS" 2>/dev/null || true
  ip netns del "$MOLE_NS" 2>/dev/null || true
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
[ "$(id -u)" = 0 ] || { echo "run as root (use: sudo -E bash lab/netns-smoke.sh)" >&2; exit 1; }
need ip; need python3; need openssl
MOLE_FW="${MOLE_FW:-auto}"   # firewall backend: auto|iptables|nft
case "$MOLE_FW" in nft) need nft ;; iptables) need iptables ;; *) command -v iptables >/dev/null || command -v nft >/dev/null || { echo "missing iptables/nft" >&2; exit 1; } ;; esac
UV="$(command -v uv || true)"
[ -n "$UV" ] || { echo "uv not found in PATH; run via: sudo -E env PATH=\"\$PATH\" bash lab/netns-smoke.sh" >&2; exit 1; }
# Prepare the project venv once (needs network) so the in-namespace `uv run
# --no-sync` below works offline.
(cd "$ROOT" && "$UV" sync --quiet) || { echo "uv sync failed" >&2; exit 1; }

cleanup
mkdir -p "$SESSION"

ip netns add "$GW_NS"
ip netns add "$TARGET_NS"
ip netns add "$MOLE_NS"
ip link add "$BR" type bridge
ip link set "$BR" up

mkport() {
  local ns="$1" hostif="$2" nsif="$3" ipaddr="$4"
  ip link add "$hostif" type veth peer name "$nsif"
  ip link set "$hostif" master "$BR"
  ip link set "$hostif" up
  ip link set "$nsif" netns "$ns"
  ip -n "$ns" link set lo up
  ip -n "$ns" link set "$nsif" name eth0
  ip -n "$ns" addr add "$ipaddr/24" dev eth0
  ip -n "$ns" link set eth0 up
}

mkport "$GW_NS" vgw0 vgw1 "$NET.1"
mkport "$TARGET_NS" vtgt0 vtgt1 "$NET.10"
mkport "$MOLE_NS" vmole0 vmole1 "$NET.66"

# Default to a DETERMINISTIC path: route the target through the mole (the real
# effect of a successful ARP spoof) so the CI smoke reliably exercises the
# redirect -> proxy -> TLS -> funnel -> capture pipeline without the inherent
# race of ARP poisoning a kernel that answers who-has instantly. Set
# MOLE_LAB_ARP=1 to instead test live ARP spoofing (flaky by nature in a bridge).
if [ "${MOLE_LAB_ARP:-0}" = "1" ]; then
  ip -n "$TARGET_NS" route add default via "$NET.1" dev eth0
  MOLE_ARP_FLAG=""
else
  ip -n "$TARGET_NS" route add default via "$NET.66" dev eth0   # via mole
  # The lab "upstream" ($NET.1) is on-subnet, so a default route alone won't pull
  # its traffic through the mole; a /32 forces it (mirrors a real off-subnet dest
  # reached via the spoofed gateway).
  ip -n "$TARGET_NS" route add "$NET.1/32" via "$NET.66" dev eth0
  MOLE_ARP_FLAG="--no-arp"
fi
ip -n "$MOLE_NS" route add default via "$NET.1" dev eth0

# A tiny HTTPS server in the gateway namespace. It intentionally uses a self-signed
# cert because the upstream side is only for exercising forwarding/proxying.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$SESSION/upstream.key" -out "$SESSION/upstream.crt" -days 1 \
  -subj "/CN=telemetry.example.test" \
  -addext "subjectAltName=DNS:telemetry.example.test" >/dev/null 2>&1
cat > "$SESSION/server.py" <<'PY'
import http.server, ssl
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'hello from upstream\n')
    def log_message(self, *a): pass
httpd = http.server.HTTPServer(('10.13.37.1', 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('/SESSION/upstream.crt', '/SESSION/upstream.key')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
sed -i "s#/SESSION#${SESSION}#g" "$SESSION/server.py"
ip netns exec "$GW_NS" python3 "$SESSION/server.py" & PIDS+=("$!")
sleep 1

# A real DTLS (CoAP/DTLS) echo server in the gateway namespace, to exercise the
# transparent DTLS MITM path (UDP 5684 redirect + IP_RECVORIGDSTADDR + conntrack).
cat > "$SESSION/dtls_server.py" <<'PY'
import socket, datetime as dt
from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from trustfall.dtls import DatagramDTLS
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "telemetry.example.test")])
now = dt.datetime.now(dt.UTC)
cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256()))
ctx = SSL.Context(SSL.DTLS_METHOD)
ctx.use_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, cert.public_bytes(serialization.Encoding.PEM)))
ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.13.37.1", 5684))
_peek, peer = s.recvfrom(65535, socket.MSG_PEEK); s.connect(peer)
ep = DatagramDTLS(ctx, s, server=True)
ep.do_handshake()
while True:
    d = ep.recv(2.0)
    if d is None:
        break
    if d:
        ep.send(b"ack:" + d)
PY
ip netns exec "$GW_NS" "$UV" run --no-sync --project "$ROOT" python "$SESSION/dtls_server.py" >"$SESSION/dtls_server.log" 2>&1 & PIDS+=("$!")
sleep 2

# Start Trustfall in the mole namespace. ARP spoofing and iptables happen only
# inside the isolated lab namespaces/bridge.
ip netns exec "$MOLE_NS" "$UV" run --no-sync --project "$ROOT" python -m trustfall.cli "$NET.10" \
  --out "$SESSION/mole" --include-udp --retest wait --jsonl --firewall "$MOLE_FW" $MOLE_ARP_FLAG >"$SESSION/mole.log" 2>"$SESSION/mole.err" & PIDS+=("$!")
MOLE_PID="$!"
for i in $(seq 1 20); do
  if grep -q 'arp_spoofing started\|proxy listening' "$SESSION/mole.log" 2>/dev/null; then break; fi
  sleep 1
done
if ! grep -q 'proxy listening' "$SESSION/mole.log" 2>/dev/null; then
  echo "[-] Mole did not start in time" >&2
  cat "$SESSION/mole.err" >&2 || true
  exit 2
fi
sleep 1  # let the proxy/netfilter settle before the first client connects

cat > "$SESSION/client.py" <<'PY'
import socket, ssl, sys
verify = sys.argv[1] == 'verify'
ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
try:
    s = socket.create_connection(('10.13.37.1', 443), timeout=5)
    t = ctx.wrap_socket(s, server_hostname='telemetry.example.test')
    t.sendall(b'GET /device-checkin?id=smoke HTTP/1.1\r\nHost: telemetry.example.test\r\nConnection: close\r\n\r\n')
    print(t.recv(200).decode(errors='ignore'))
    t.close()
except Exception as e:
    print(type(e).__name__ + ': ' + str(e))
PY

# First connection should be rejected by a validating client.
if [ "${MOLE_LAB_ARP:-0}" = "1" ]; then
  ip -n "$TARGET_NS" neigh flush all || true
  sleep 3
fi
echo "[+] target neighbor table:"
ip -n "$TARGET_NS" neigh show || true

echo "[+] validating client attempt; expected cert failure"
ip netns exec "$TARGET_NS" python3 "$SESSION/client.py" verify || true
sleep 1

# Second connection accepts any cert, proving the transparent path/proxy works and payload capture occurs.
echo "[+] insecure client attempt; expected HTTP response through MITM"
ip netns exec "$TARGET_NS" python3 "$SESSION/client.py" insecure || true
sleep 1

# Plaintext CoAP datagram to exercise passive CoAP parsing (new feature).
echo "[+] coap datagram; expected COAP event"
ip netns exec "$TARGET_NS" python3 - <<'PY' || true
import socket
# CON GET /status (ver=1,type=0,tkl=0 ; code 0.01 ; mid ; Uri-Path option 11 "status")
pkt = bytes([0x40, 0x01, 0x12, 0x34, (11 << 4) | 6]) + b"status"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt, ("10.13.37.1", 5683))
s.close()
PY
sleep 1

# DTLS (CoAP-over-DTLS) exchange; expected DTLS interception + decrypted capture.
echo "[+] dtls exchange; expected DTLS interception + capture"
cat > "$SESSION/dtls_client.py" <<'PY'
import socket
from OpenSSL import SSL
from trustfall.dtls import DatagramDTLS
ctx = SSL.Context(SSL.DTLS_METHOD); ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("10.13.37.1", 5684))
ep = DatagramDTLS(ctx, s, server=False)
ok = ep.do_handshake()
pkt = bytes([0x40, 0x01, 0x12, 0x34, (11 << 4) | 9]) + b"telemetry" + b" token=dtls-secret"
ep.send(pkt)
echo = b""
for _ in range(12):
    g = ep.recv(0.5)
    if g:
        echo = g; break
print("dtls_client: handshake", ok, "echo", echo[:48])
PY
ip netns exec "$TARGET_NS" "$UV" run --no-sync --project "$ROOT" python "$SESSION/dtls_client.py" || true
sleep 1

# Stop the mole gracefully (SIGINT) so it runs cleanup + writes the summary,
# instead of letting the EXIT trap's `ip netns del` SIGKILL it mid-shutdown.
kill -INT "$MOLE_PID" 2>/dev/null || true
for i in $(seq 1 10); do
  [ -f "$SESSION/mole/summary.txt" ] && break
  sleep 0.5
done

echo "[+] Mole log: $SESSION/mole.log"
tail -n +1 "$SESSION/mole.log" || true

echo "[+] Payload files:"
find "$SESSION/mole" -type f -maxdepth 4 -print 2>/dev/null || true

echo "[+] DTLS server log:"; cat "$SESSION/dtls_server.log" 2>/dev/null || true
DTLS_ACCEPTED=$(grep '"proto": "dtls"' "$SESSION/mole.log" 2>/dev/null | grep -c '"result": "accepted"' || true)
echo "[+] DTLS accepted interceptions: $DTLS_ACCEPTED"

if grep -q '"result": "accepted"' "$SESSION/mole.log" && find "$SESSION/mole" -name client.bin -size +0c | grep -q . && [ -f "$SESSION/mole/summary.txt" ] && grep -q '"kind": "COAP"' "$SESSION/mole.log" && [ "${DTLS_ACCEPTED:-0}" -ge 1 ]; then
  echo "[+] smoke test passed (intercept + capture + summary + coap + dtls)"
else
  echo "[-] smoke test did not observe accepted MITM + payload + coap + dtls; inspect $SESSION" >&2
  exit 2
fi

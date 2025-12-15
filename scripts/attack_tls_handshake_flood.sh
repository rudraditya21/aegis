#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

CONFIG_ROOT="$(mktemp -d)"
if command -v realpath >/dev/null 2>&1; then
  export AEGIS_CONFIG_ROOT="$(realpath "$CONFIG_ROOT")"
  export FIREWALL_CONFIG_ROOT="$AEGIS_CONFIG_ROOT"
else
  export AEGIS_CONFIG_ROOT="$(cd "$CONFIG_ROOT" && pwd)"
  export FIREWALL_CONFIG_ROOT="$AEGIS_CONFIG_ROOT"
fi
unset AEGIS_CONFIG_READONLY
unset FIREWALL_CONFIG_READONLY
RULES_FILE="$FIREWALL_CONFIG_ROOT/rules.conf"
POLICY_FILE="$FIREWALL_CONFIG_ROOT/policies.conf"
trap 'rm -rf "$CONFIG_ROOT"' EXIT

cat >"$RULES_FILE" <<'RULES'
allow cidr 0.0.0.0/0 ingress
default deny ingress
RULES
echo >"$POLICY_FILE"

PKT_FILE="$FIREWALL_CONFIG_ROOT/tls_flood.hex"
rm -f "$PKT_FILE"

# Generate many TLS ClientHello packets over a single source, random SNI-like payload.
python3 - <<'PY' >"$PKT_FILE"
import random, struct, string

def tls_client_hello_payload():
    # Minimal TLS record header + handshake header; contents arbitrary but consistent with ClientHello.
    random_sni = ''.join(random.choice(string.ascii_lowercase) for _ in range(6)).encode()
    hello_body = b"\x01" + b"\x00\x00\x10" + b"\x03\x03" + b"\x00"*14  # type=ClientHello, dummy body
    record_len = len(hello_body)
    record = b"\x16\x03\x01" + struct.pack("!H", record_len) + hello_body + random_sni
    return record

def tcp_packet(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H", 0x0800)
    ver_ihl = (4 << 4) | 5
    total_len = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, random.randint(1, 65000), 0x4000, 64, 6, 0, src_ip, dst_ip)
    offset_flags = (5 << 12) | flags
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags, 0x7210, 0, 0)
    frame = eth + ip + tcp + payload
    print(" ".join(f"{b:02x}" for b in frame))

dst_ip = 0x0a000002
src_ip = 0x0a0000f4
sport = 45000
dport = 443

# Handshake
tcp_packet(src_ip, dst_ip, sport, dport, 1, 0, 0x02)   # SYN
tcp_packet(src_ip, dst_ip, sport, dport, 2, 1, 0x10)   # ACK -> Established

# Flood of ClientHello packets on the same flow.
seq = 3
for _ in range(800):
    payload = tls_client_hello_payload()
    tcp_packet(src_ip, dst_ip, sport, dport, seq, 1, 0x18, payload)
    seq += 1
PY

echo "[attack] Replaying TLS handshake flood..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --block-rate-anomaly --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"allowed"){split($i,a,"=");print a[2]}}}')
dropped=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"dropped"){split($i,a,"=");print a[2]}}}')
rate_alerts=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"rate_alerts"){split($i,a,"=");print a[2]}}}')

if [ -z "$rate_alerts" ] || [ "$rate_alerts" -lt 1 ]; then
  echo "Rate anomaly was not detected for TLS handshake flood" >&2
  exit 1
fi
if [ -z "$dropped" ] || [ "$dropped" -lt 300 ]; then
  echo "TLS handshake flood was not sufficiently throttled" >&2
  exit 1
fi
if [ -n "$allowed" ] && [ "$allowed" -gt 700 ]; then
  echo "Too many TLS handshake packets were allowed" >&2
  exit 1
fi

echo "[attack] TLS handshake flood simulation passed (allowed=${allowed:-0} dropped=${dropped:-0} rate_alerts=${rate_alerts:-0})"

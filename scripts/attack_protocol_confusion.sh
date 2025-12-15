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

PKT_FILE="$FIREWALL_CONFIG_ROOT/protocol_confusion.hex"
rm -f "$PKT_FILE"

python3 - <<'PY' >"$PKT_FILE"
import struct

def tcp_pkt(src_ip, sport, dport, seq, payload=b"", flags=0x18):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H", 0x0800)
    ver_ihl = (4 << 4) | 5
    total_len = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, 0x8888, 0x4000, 64, 6, 0, src_ip, 0x0a000002)
    offset_flags = (5 << 12) | flags
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 1, offset_flags, 0x7210, 0, 0)
    frame = eth + ip + tcp + payload
    print(" ".join(f"{b:02x}" for b in frame))

# HTTP on non-standard port 4443
tcp_pkt(0x0a0000f1, 50000, 4443, 1, b"", flags=0x02)  # SYN
tcp_pkt(0x0a0000f1, 50000, 4443, 2, b"", flags=0x10)  # ACK
http_payload = b"GET /admin HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
tcp_pkt(0x0a0000f1, 50000, 4443, 3, http_payload)

# TLS ClientHello on port 80
tcp_pkt(0x0a0000f2, 50010, 80, 1, b"", flags=0x02)
tcp_pkt(0x0a0000f2, 50010, 80, 2, b"", flags=0x10)
tls_hello = b"\\x16\\x03\\x01\\x00\\x00\\x01"
tcp_pkt(0x0a0000f2, 50010, 80, 3, tls_hello)
PY

echo "[attack] Replaying protocol confusion cases..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~/^allowed/){split($i,a,"=");print a[2]}}}')
alerts=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~/^alerts/){split($i,a,"=");print a[2]}}}')

if [ -z "$alerts" ] || [ "$alerts" -lt 1 ]; then
  echo "Protocol confusion was not detected" >&2
  exit 1
fi
echo "[attack] Protocol confusion simulation passed (allowed=${allowed:-0} alerts=${alerts:-0})"

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

PKT_FILE="$FIREWALL_CONFIG_ROOT/unicode_encoding.hex"
rm -f "$PKT_FILE"

python3 - <<'PY' >"$PKT_FILE"
import struct

def tcp_pkt(seq, payload=b"", flags=0x18):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H", 0x0800)
    ver_ihl = (4 << 4) | 5
    total_len = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, 0x7777, 0x4000, 64, 6, 0, 0x0a0000f0, 0x0a000002)
    offset_flags = (5 << 12) | flags
    tcp = struct.pack("!HHIIHHHH", 44000, 80, seq, 1, offset_flags, 0x7210, 0, 0)
    frame = eth + ip + tcp + payload
    print(" ".join(f"{b:02x}" for b in frame))

# Handshake-ish priming
tcp_pkt(1, b"", flags=0x02)  # SYN
tcp_pkt(2, b"", flags=0x10)  # ACK

# URL-encoded and double-encoded path traversal, plus UTF-8 BOM + encoded payload.
payloads = [
    b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\\r\\nHost: ex.com\\r\\n\\r\\n",
    b"GET /%252e%252e/%252e%252e/etc/passwd HTTP/1.1\\r\\nHost: ex.com\\r\\n\\r\\n",
    b"\\xef\\xbb\\xbfGET /..%2fetc/passwd HTTP/1.1\\r\\nHost: ex.com\\r\\n\\r\\n",
]

seq = 3
for p in payloads:
    tcp_pkt(seq, p)
    seq += 1
PY

echo "[attack] Replaying Unicode/encoding attacks..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~/^allowed/){split($i,a,"=");print a[2]}}}')
dropped=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~/^dropped/){split($i,a,"=");print a[2]}}}')
alerts=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~/^alerts/){split($i,a,"=");print a[2]}}}')

if [ -z "$alerts" ] || [ "$alerts" -lt 1 ]; then
  echo "Encoded/Unicode attack was not detected" >&2
  exit 1
fi
if [ -z "$dropped" ] || [ "$dropped" -lt 1 ]; then
  echo "Encoded/Unicode attack was not dropped" >&2
  exit 1
fi

echo "[attack] Unicode/encoding attack simulation passed (allowed=${allowed:-0} dropped=${dropped:-0} alerts=${alerts:-0})"

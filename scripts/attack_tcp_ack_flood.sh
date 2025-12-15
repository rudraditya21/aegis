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

PKT_FILE="$FIREWALL_CONFIG_ROOT/ack_flood.hex"
rm -f "$PKT_FILE"

# Generate 2000 stray ACKs without prior SYN handshakes
python3 - <<'PY' >"$PKT_FILE"
import struct
def ack(src_ip, sport, dst_ip=0x0a000002, dport=80):
    eth=bytes.fromhex("ffe1e2e3e4e5001122334455")+struct.pack("!H",0x0800)
    ip=struct.pack("!BBHHHBBHII",(4<<4)|5,0,40,1,0x4000,64,6,0,src_ip,dst_ip)
    tcp=struct.pack("!HHIIHHHH",sport,dport,12345,0,(5<<12)|0x10,65535,0,0)
    frame=eth+ip+tcp
    print(" ".join(f"{b:02x}" for b in frame))

src_base=0x0a000100
for i in range(2000):
    ack(src_base + i, 20000 + i)
PY

echo "[attack] Replaying TCP ACK flood..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"allowed"){split($i,a,"=");print a[2]}}}')
dropped=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"dropped"){split($i,a,"=");print a[2]}}}')

if [ -z "$dropped" ] || [ "$dropped" -lt 1500 ]; then
  echo "Expected most ACKs to be dropped as invalid state" >&2
  exit 1
fi
if [ -z "$allowed" ] || [ "$allowed" -gt 100 ]; then
  echo "Too many stray ACKs were allowed" >&2
  exit 1
fi

echo "[attack] TCP ACK flood simulation passed (allowed=$allowed dropped=$dropped)"

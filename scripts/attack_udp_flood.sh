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

PKT_FILE="$FIREWALL_CONFIG_ROOT/udp_flood.hex"
rm -f "$PKT_FILE"

# Generate 3000 UDP packets to random ports; protector should rate-limit.
python3 - <<'PY' >"$PKT_FILE"
import struct, random
def udp(src_ip, sport, dst_ip=0x0a000002, dport=53):
    payload=b'\x00'*8
    eth=bytes.fromhex("ffe1e2e3e4e5001122334455")+struct.pack("!H",0x0800)
    ver_ihl=(4<<4)|5
    total_len=20+8+len(payload)
    ip=struct.pack("!BBHHHBBHII",ver_ihl,0,total_len,random.randint(1,65000),0x4000,64,17,0,src_ip,dst_ip)
    udp_hdr=struct.pack("!HHHH",sport,dport,8+len(payload),0)
    frame=eth+ip+udp_hdr+payload
    print(" ".join(f"{b:02x}" for b in frame))

for i in range(3000):
    udp(0x0a000100 + i, 10000 + i, 0x0a000002, random.randint(1000, 65000))
PY

echo "[attack] Replaying UDP flood..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"allowed"){split($i,a,"=");print a[2]}}}')
dropped=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"dropped"){split($i,a,"=");print a[2]}}}')
blocked=$(echo "$OUTPUT" | awk '/blocked_by_protector/ {for(i=1;i<=NF;i++){if($i~"blocked_by_protector"){split($i,a,"=");print a[2]}}}')

if [ -z "$blocked" ] || [ "$blocked" -lt 100 ]; then
  echo "Protector did not rate-limit UDP flood" >&2
  exit 1
fi
if [ -z "$dropped" ] || [ "$dropped" -lt 1000 ]; then
  echo "Too many UDP flood packets were allowed" >&2
  exit 1
fi

echo "[attack] UDP flood simulation passed (allowed=${allowed:-0} dropped=${dropped:-0} blocked=$blocked)"

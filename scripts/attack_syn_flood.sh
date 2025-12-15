#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

# Config root sandbox
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

# Allow default ingress; no special policies needed.
cat >"$RULES_FILE" <<'RULES'
allow cidr 0.0.0.0/0 ingress
default deny ingress
RULES
echo >"$POLICY_FILE"

PKT_FILE="$FIREWALL_CONFIG_ROOT/syn_flood.hex"
rm -f "$PKT_FILE"

# Generate 2000 SYN packets from same source to trigger protector limits,
# plus 5 legitimate ACK packets to confirm good traffic passes.
python3 - <<'PY' >"$PKT_FILE"
import struct
def syn(src_ip, sport, dst_ip=0x0a000002, dport=80):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H",0x0800)
    ip = struct.pack("!BBHHHBBHII",(4<<4)|5,0,40,1,0x4000,64,6,0,src_ip,dst_ip)
    tcp = struct.pack("!HHIIHHHH",sport,dport,1,0,(5<<12)|0x02,65535,0,0)
    frame = eth+ip+tcp
    print(" ".join(f"{b:02x}" for b in frame))

def ack(src_ip, sport, dst_ip=0x0a000002, dport=80):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H",0x0800)
    ip = struct.pack("!BBHHHBBHII",(4<<4)|5,0,40,2,0x4000,64,6,0,src_ip,dst_ip)
    tcp = struct.pack("!HHIIHHHH",sport,dport,1,1,(5<<12)|0x10,65535,0,0)
    frame = eth+ip+tcp
    print(" ".join(f"{b:02x}" for b in frame))

base_src = 0x0a000001
for i in range(2000):
    syn(base_src, 40000 + i)
for i in range(5):
    ack(base_src, 50000 + i)
PY

echo "[attack] Replaying SYN flood to test protector..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

blocked=$(echo "$OUTPUT" | awk '/blocked_by_protector/ {for(i=1;i<=NF;i++){if($i~"blocked_by_protector"){split($i,a,"=");print a[2]}}}')
allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"allowed"){split($i,a,"=");print a[2]}}}')
if [ -z "$blocked" ]; then
  echo "Blocked_by_protector metric missing" >&2
  exit 1
fi
if [ "$blocked" -eq 0 ]; then
  echo "Protector did not block any SYNs" >&2
  exit 1
fi
if [ -z "$allowed" ] || [ "$allowed" -lt 5 ]; then
  echo "Legitimate ACK traffic was not allowed as expected" >&2
  exit 1
fi

echo "[attack] SYN flood simulation passed (blocked_by_protector=$blocked, allowed=$allowed)"

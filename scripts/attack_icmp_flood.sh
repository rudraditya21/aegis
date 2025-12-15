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

PKT_FILE="$FIREWALL_CONFIG_ROOT/icmp_flood.hex"
rm -f "$PKT_FILE"

# Generate many ICMP echo requests, plus a handful with fragmentation flag set.
python3 - <<'PY' >"$PKT_FILE"
import random, struct

def icmp_echo(src_ip, dst_ip=0x0a000002, ident=0x1234, seq=1, frag=False):
    payload = b'\x00' * 8
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H", 0x0800)
    ver_ihl = (4 << 4) | 5
    total_len = 20 + 8 + len(payload)
    flags_offset = 0x0000
    if frag:
        flags_offset = 0x2000  # MF flag set, offset zero
    ip = struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, random.randint(1, 65000),
        flags_offset, 64, 1, 0, src_ip, dst_ip)
    icmp = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    frame = eth + ip + icmp
    print(" ".join(f"{b:02x}" for b in frame))

# 1000 normal echo requests from same source to trigger rate limit.
for i in range(1000):
    icmp_echo(0x0a0000f0, seq=i)

# 50 fragmented echo requests to exercise parser + limits.
for i in range(50):
    icmp_echo(0x0a0000f0, seq=2000 + i, frag=True)
PY

echo "[attack] Replaying ICMP flood..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"allowed"){split($i,a,"=");print a[2]}}}')
dropped=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"dropped"){split($i,a,"=");print a[2]}}}')
blocked=$(echo "$OUTPUT" | awk '/blocked_by_protector/ {for(i=1;i<=NF;i++){if($i~"blocked_by_protector"){split($i,a,"=");print a[2]}}}')

# We expect most of the 1050 ICMP packets to be throttled.
if [ -z "$blocked" ] || [ "$blocked" -lt 400 ]; then
  echo "Protector did not rate-limit ICMP flood" >&2
  exit 1
fi
if [ -z "$allowed" ] || [ "$allowed" -gt 300 ]; then
  echo "Too many ICMP flood packets were allowed" >&2
  exit 1
fi

echo "[attack] ICMP flood simulation passed (allowed=${allowed:-0} dropped=${dropped:-0} blocked=$blocked)"

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

PKT_FILE="$FIREWALL_CONFIG_ROOT/fragmentation.hex"
rm -f "$PKT_FILE"

# Build overlapping and tiny IPv4 fragments; parser should reject fragments entirely.
python3 - <<'PY' >"$PKT_FILE"
import struct

def frag(offset_words, mf, payload_len):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H", 0x0800)
    ver_ihl = (4 << 4) | 5
    total_len = 20 + payload_len
    flags_offset = ((0x1 if mf else 0) << 13) | (offset_words & 0x1FFF)
    ip = struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, 0x1111, flags_offset, 64, 6, 0,
        0x0a000001, 0x0a000002)
    payload = bytes(range(payload_len))
    frame = eth + ip + payload
    print(" ".join(f"{b:02x}" for b in frame))

# First fragment offset 0, MF set.
frag(0, True, 16)
# Second fragment overlaps (offset 1 word = 8 bytes), MF set.
frag(1, True, 16)
# Tiny fragment near end.
frag(4, False, 8)
PY

echo "[attack] Replaying fragmentation attacks..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"allowed"){split($i,a,"=");print a[2]}}}')
blocked=$(echo "$OUTPUT" | awk '/blocked_by_protector/ {for(i=1;i<=NF;i++){if($i~"blocked_by_protector"){split($i,a,"=");print a[2]}}}')
dropped=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"dropped"){split($i,a,"=");print a[2]}}}')

if [ -z "$allowed" ] || [ "$allowed" -gt 0 ]; then
  echo "Fragmented packets should not be allowed" >&2
  exit 1
fi
if [ -z "$dropped" ] || [ "$dropped" -lt 3 ]; then
  echo "Fragmented packets were not dropped" >&2
  exit 1
fi

echo "[attack] Fragmentation attack simulation passed (allowed=${allowed:-0} dropped=${dropped:-0} blocked=${blocked:-0})"

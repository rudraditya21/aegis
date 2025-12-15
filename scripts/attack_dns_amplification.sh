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

PKT_FILE="$FIREWALL_CONFIG_ROOT/dns_amplification.hex"
rm -f "$PKT_FILE"

# Simulate DNS amplification responses: large UDP payloads from many spoofed sources to victim ports.
python3 - <<'PY' >"$PKT_FILE"
import random, struct

def udp_packet(src_ip, dst_ip, sport, dport, payload_len=400):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H", 0x0800)
    ver_ihl = (4 << 4) | 5
    total_len = 20 + 8 + payload_len
    ip = struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, random.randint(1, 65000), 0x4000, 64, 17, 0,
        src_ip, dst_ip)
    udp = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)
    payload = bytes([0xAB]) * payload_len  # large response body
    frame = eth + ip + udp + payload
    print(" ".join(f"{b:02x}" for b in frame))

dst_ip = 0x0a000002
# 2000 large responses from many spoofed resolvers to victim random ports.
for i in range(2000):
    src_ip = 0x0a000100 + i  # varying sources
    dport = random.randint(1024, 65000)
    udp_packet(src_ip, dst_ip, 53, dport)
PY

echo "[attack] Replaying DNS amplification simulation..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"allowed"){split($i,a,"=");print a[2]}}}')
dropped=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~"dropped"){split($i,a,"=");print a[2]}}}')
blocked=$(echo "$OUTPUT" | awk '/blocked_by_protector/ {for(i=1;i<=NF;i++){if($i~"blocked_by_protector"){split($i,a,"=");print a[2]}}}')

# Expect rate limiting: majority should be dropped/blocked.
if [ -z "$blocked" ] || [ "$blocked" -lt 600 ]; then
  echo "Protector did not sufficiently rate-limit DNS amplification" >&2
  exit 1
fi
if [ -n "$allowed" ] && [ "$allowed" -gt 1300 ]; then
  echo "Too many DNS amplification packets were allowed" >&2
  exit 1
fi

echo "[attack] DNS amplification simulation passed (allowed=${allowed:-0} dropped=${dropped:-0} blocked=${blocked:-0})"

#!/usr/bin/env bash
# Regression suite: replay known attacks + safe traffic to guard against FP/FN.
set -euo pipefail
cd -- "$(dirname "$0")/.."

echo "[regress] Running unit tests..."
cargo test

echo "[regress] Running attack simulations..."
for f in \
  scripts/attack_syn_flood.sh \
  scripts/attack_tcp_ack_flood.sh \
  scripts/attack_udp_flood.sh \
  scripts/attack_icmp_flood.sh \
  scripts/attack_fragmentation.sh \
  scripts/attack_dns_amplification.sh \
  scripts/attack_http_flood.sh \
  scripts/attack_slowloris.sh \
  scripts/attack_http_obfuscation.sh \
  scripts/attack_unicode_encoding.sh \
  scripts/attack_tls_handshake_flood.sh \
  scripts/attack_fragmented_tls_clienthello.sh \
  scripts/attack_tcp_segmentation.sh \
  scripts/attack_protocol_confusion.sh \
  scripts/attack_exploit_signatures.sh \
  scripts/attack_c2_beacon.sh
do
  echo "[regress] $f"
  bash "$f"
done

echo "[regress] Running known-safe traffic check (should allow)..."
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
echo "allow cidr 0.0.0.0/0 ingress" >"$RULES_FILE"
echo "default allow ingress" >>"$RULES_FILE"

SAFE_HEX="$(
python3 - <<'PY'
import struct
def pkt():
    eth=bytes.fromhex("ffe1e2e3e4e5001122334455")+struct.pack("!H",0x0800)
    ver_ihl=(4<<4)|5
    payload=b"GET /health HTTP/1.1\r\nHost: ok\r\n\r\n"
    total_len=20+20+len(payload)
    ip=struct.pack("!BBHHHBBHII",ver_ihl,0,total_len,1,0x4000,64,6,0,0x0a00000a,0x0a00000b)
    tcp=struct.pack("!HHIIHHHH",40000,80,1,0,(5<<12)|0x18,65535,0,0)
    frame=eth+ip+tcp+payload
    print(" ".join(f"{b:02x}" for b in frame))
pkt()
PY
)"

out=$(cargo run -p aegis --quiet -- eval --rules "$RULES_FILE" --direction ingress --hex "$SAFE_HEX" --no-logs --disable-ips --disable-ids 2>&1)
echo "$out"
if ! echo "$out" | grep -q "Action: Allow"; then
  echo "[regress] Safe traffic was not allowed" >&2
  exit 1
fi

rm -rf "$CONFIG_ROOT"
echo "[regress] Regression suite completed."

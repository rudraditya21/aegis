#!/usr/bin/env bash
# Long-running stability soak. Default duration: 1 hour; adjust via SOAK_DURATION (seconds).
# Mixes benign evals with periodic attack simulations; captures RSS/CPU snapshots.
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
trap 'rm -rf "$CONFIG_ROOT"' EXIT

cat >"$RULES_FILE" <<'RULES'
allow cidr 10.0.0.0/8 ingress
deny port tcp 22 ingress
default deny ingress
RULES

SOAK_DURATION=${SOAK_DURATION:-3600} # seconds; set to 604800 for 7 days, 1209600 for 14 days
SAMPLE_INTERVAL=${SAMPLE_INTERVAL:-60} # seconds between resource snapshots
ATTACK_INTERVAL=${ATTACK_INTERVAL:-300} # seconds between attack batches
START_TS=$(date +%s)
NEXT_ATTACK=$((START_TS + ATTACK_INTERVAL))

echo "[soak] Building release binary..."
cargo build -p aegis --release >/dev/null

echo "[soak] Starting long-run for ${SOAK_DURATION}s (override SOAK_DURATION)..."

# Simple benign payload
HTTP_HEX="$(
python3 - <<'PY'
import struct
def pkt():
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H",0x0800)
    ver_ihl=(4<<4)|5
    payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    total_len=20+20+len(payload)
    ip=struct.pack("!BBHHHBBHII",ver_ihl,0,total_len,1,0x4000,64,6,0,0x0a000001,0x0a000002)
    tcp=struct.pack("!HHIIHHHH",12345,80,1,0,(5<<12)|0x18,65535,0,0)
    frame=eth+ip+tcp+payload
    print(" ".join(f"{b:02x}" for b in frame))
pkt()
PY
)"

log_resource() {
  ts=$(date +%s)
  rss=$(ps -o rss= -p $$ 2>/dev/null || echo "n/a")
  cpu_load=$(ps -o %cpu= -p $$ 2>/dev/null || echo "n/a")
  echo "[soak][${ts}] rss_kb=${rss} cpu_pct=${cpu_load}"
}

run_attacks() {
  echo "[soak] Running attack batch..."
  bash scripts/attack_syn_flood.sh >/dev/null || true
  bash scripts/attack_udp_flood.sh >/dev/null || true
  bash scripts/attack_http_flood.sh >/dev/null || true
  bash scripts/attack_tls_handshake_flood.sh >/dev/null || true
}

while true; do
  now=$(date +%s)
  if (( now - START_TS >= SOAK_DURATION )); then
    echo "[soak] Duration reached; exiting."
    break
  fi

  # benign eval burst
  for _ in $(seq 1 1000); do
    ./target/release/aegis eval --rules "$RULES_FILE" --direction ingress --hex "$HTTP_HEX" --no-logs --disable-ids --disable-ips >/dev/null
  done

  # periodic attacks
  if (( now >= NEXT_ATTACK )); then
    run_attacks
    NEXT_ATTACK=$((now + ATTACK_INTERVAL))
  fi

  # resource sample
  log_resource
  sleep "$SAMPLE_INTERVAL"
done

echo "[soak] Completed."

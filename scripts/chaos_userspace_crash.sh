#!/usr/bin/env bash
# Chaos test: start aegis capture (dummy) then kill to observe fail-open/closed.
# This script assumes the firewall binary respects FIREWALL_FAIL_MODE (open/closed) via env/cli.
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
allow cidr 0.0.0.0/0 ingress
default deny ingress
RULES

echo "[chaos] Building release binary..."
cargo build -p aegis --release >/dev/null

FAIL_MODE=${FAIL_MODE:-open} # set FAIL_MODE=closed to test fail-closed
export FIREWALL_FAIL_MODE="$FAIL_MODE"

echo "[chaos] Starting aegis capture (dummy iface lo, count=100)..."
./target/release/aegis capture --rules "$RULES_FILE" --iface lo --count 100 --no-logs --disable-ids --disable-ips >/dev/null &
FW_PID=$!
sleep 1

echo "[chaos] Killing aegis (pid=$FW_PID)..."
kill -9 "$FW_PID" || true
wait "$FW_PID" 2>/dev/null || true

echo "[chaos] Checking fail mode expectation ($FAIL_MODE)..."
if [ "$FAIL_MODE" = "open" ]; then
  echo "[chaos] Expect downstream to allow traffic (fail-open). Verify externally if desired."
else
  echo "[chaos] Expect downstream to block traffic (fail-closed). Verify externally if desired."
fi

echo "[chaos] Userspace crash test script completed (manual verification required for dataplane behavior)."

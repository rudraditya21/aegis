#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

CONFIG_ROOT=$(mktemp -d)
CONFIG_ROOT=$(python3 - <<'PY' "$CONFIG_ROOT"
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
)
export AEGIS_CONFIG_ROOT="$CONFIG_ROOT"
export FIREWALL_CONFIG_ROOT="$CONFIG_ROOT"
RULES="$CONFIG_ROOT/rules.conf"
trap 'rm -rf "$CONFIG_ROOT"' EXIT

cat >"$RULES" <<'RULES'
allow cidr 10.0.0.0/8 ingress
deny port tcp 22 ingress
default deny ingress
RULES

cargo build -p aegis --release >/dev/null

sudo AEGIS_CONFIG_ROOT="$CONFIG_ROOT" FIREWALL_CONFIG_ROOT="$CONFIG_ROOT" \
  ./target/release/aegis capture \
  --rules "$RULES" \
  --iface "${IFACE:-en0}" \
  --count "${COUNT:-200}" \
  --no-logs

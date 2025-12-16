#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

CONFIG_ROOT="${CONFIG_ROOT:-/etc/aegis}"
RULES="${RULES:-$CONFIG_ROOT/rules/l3l4.rules}"

mkdir -p "$CONFIG_ROOT/rules" "$CONFIG_ROOT/logs" "$CONFIG_ROOT/state" "$CONFIG_ROOT/intel"
cat >"$RULES" <<'RULES'
deny port udp 443 ingress
deny port tcp 22 ingress
allow cidr 10.0.0.0/8 ingress
default deny ingress
RULES

cargo build -p aegis --release >/dev/null

sudo AEGIS_CONFIG_ROOT="$CONFIG_ROOT" FIREWALL_CONFIG_ROOT="$CONFIG_ROOT" \
  ./target/release/aegis capture \
  --rules "$RULES" \
  --iface "${IFACE:-en0}" \
  --count "${COUNT:-200}" \
  --no-logs

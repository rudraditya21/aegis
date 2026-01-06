#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

CONFIG_ROOT="${CONFIG_ROOT:-}"
if [[ -z "$CONFIG_ROOT" ]]; then
  CONFIG_ROOT="$(mktemp -d)"
  trap 'rm -rf "$CONFIG_ROOT"' EXIT
fi
export AEGIS_CONFIG_ROOT="$CONFIG_ROOT"
export FIREWALL_CONFIG_ROOT="$CONFIG_ROOT"
RULES="${RULES:-$CONFIG_ROOT/rules/l3l4.rules}"

mkdir -p "$CONFIG_ROOT/rules" "$CONFIG_ROOT/logs" "$CONFIG_ROOT/state" "$CONFIG_ROOT/intel"
cat >"$RULES" <<'RULES'
deny port udp 443 ingress
deny port tcp 22 ingress
allow cidr 10.0.0.0/8 ingress
default deny ingress
RULES

cargo build -p aegis --release >/dev/null

if [[ ${EUID} -ne 0 ]]; then
  echo "[capture] Skipping live capture; requires elevated permissions."
  exit 0
fi

if [[ -z "${IFACE:-}" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    IFACE="lo0"
  else
    IFACE="lo"
  fi
fi

./target/release/aegis capture \
  --rules "$RULES" \
  --iface "$IFACE" \
  --count "${COUNT:-200}" \
  --no-logs

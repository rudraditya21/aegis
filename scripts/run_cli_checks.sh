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
RULES_FILE="$FIREWALL_CONFIG_ROOT/rules.conf"
trap 'rm -rf "$CONFIG_ROOT"' EXIT

echo "allow cidr 10.0.0.0/8 ingress" >> "$RULES_FILE"
echo "deny port tcp 22 ingress" >> "$RULES_FILE"
echo "default deny ingress" >> "$RULES_FILE"

FRAME_HEX="ff e1 e2 e3 e4 e5 00 11 22 33 44 55 81 00 80 02 08 00 \
45 00 00 28 00 01 40 00 40 06 00 00 0a 00 00 01 0a 00 00 02 \
1f 90 00 50 00 00 00 01 00 00 00 00 50 10 72 10 00 00 00 00"

echo "Evaluating sample packet against rules..."
cargo run -p aegis -- eval --rules "$RULES_FILE" --direction ingress --hex "$FRAME_HEX"

echo "Listing rules..."
cargo run -p aegis -- list-rules --rules "$RULES_FILE"

echo "Removing rule 2..."
cargo run -p aegis -- remove-rule --rules "$RULES_FILE" --id 2

echo "Rules after removal:"
cargo run -p aegis -- list-rules --rules "$RULES_FILE"

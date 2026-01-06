#!/usr/bin/env bash
# Policy correctness regression: priority, conflict resolution, shadow detection.
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
POLICIES_FILE="$FIREWALL_CONFIG_ROOT/policies.conf"
CONFLICT_RULES_FILE="$FIREWALL_CONFIG_ROOT/rules_conflict.conf"
trap 'rm -rf "$CONFIG_ROOT"' EXIT

# Rule set avoids CIDR/port conflicts (conflicts are now rejected by validation).
cat >"$RULES_FILE" <<'RULES'
allow cidr 10.0.0.0/8 ingress
allow port tcp 443 ingress
deny port tcp 22 ingress
default deny ingress
RULES

# Policy set exercises override behavior without overlapping policy conflicts.
cat >"$POLICIES_FILE" <<'POLICIES'
priority 10 action deny src 10.0.2.0/24
priority 5 action allow src 192.168.50.0/24
POLICIES

# Conflicting ruleset for validation error checks.
cat >"$CONFLICT_RULES_FILE" <<'RULES'
allow cidr 10.0.0.0/8 ingress
deny cidr 10.0.1.0/24 ingress
default deny ingress
RULES

echo "[policy] Building release binary..."
cargo build -p aegis --release >/dev/null

eval_expect() {
  local hex="$1" expect="$2" msg="$3"
  if ! out=$(./target/release/aegis eval --rules "$RULES_FILE" --policies "$POLICIES_FILE" --direction ingress --hex "$hex" --no-logs --disable-ips --disable-ids 2>&1); then
    echo "$out"
    echo "[policy] FAIL: $msg (eval failed)" >&2
    exit 1
  fi
  echo "$out"
  if ! echo "$out" | grep -q "Action: $expect"; then
    echo "[policy] FAIL: $msg (expected $expect)" >&2
    exit 1
  fi
}

eval_expect_error() {
  local rules_path="$1" hex="$2" msg="$3" needle="$4"
  if out=$(./target/release/aegis eval --rules "$rules_path" --direction ingress --hex "$hex" --no-logs --disable-ips --disable-ids 2>&1); then
    echo "$out"
    echo "[policy] FAIL: $msg (expected error)" >&2
    exit 1
  fi
  echo "$out"
  if ! echo "$out" | grep -q "$needle"; then
    echo "[policy] FAIL: $msg (missing expected error)" >&2
    exit 1
  fi
}

# Helper to craft packets quickly
packet_hex() {
python3 - "$@" <<'PY'
import struct, sys
src=sys.argv[1]; dst=sys.argv[2]; sport=int(sys.argv[3]); dport=int(sys.argv[4])
src_ip=sum(int(o)<< (24-8*i) for i,o in enumerate(src.split(".")))
dst_ip=sum(int(o)<< (24-8*i) for i,o in enumerate(dst.split(".")))
eth=bytes.fromhex("ffe1e2e3e4e5001122334455")+struct.pack("!H",0x0800)
ver_ihl=(4<<4)|5
payload=b"GET / HTTP/1.1\r\n\r\n"
total_len=20+20+len(payload)
ip=struct.pack("!BBHHHBBHII",ver_ihl,0,total_len,1,0x4000,64,6,0,src_ip,dst_ip)
tcp=struct.pack("!HHIIHHHH",sport,dport,1,0,(5<<12)|0x18,65535,0,0)
frame=eth+ip+tcp+payload
print(" ".join(f"{b:02x}" for b in frame))
PY
}

HEX_ALLOW_PORT=$(packet_hex 8.8.8.8 1.1.1.1 40000 443)
HEX_POLICY_DENY=$(packet_hex 10.0.2.5 10.0.0.9 40000 80)
HEX_POLICY_ALLOW=$(packet_hex 192.168.50.5 192.168.60.5 40000 80)
HEX_DENY_PORT=$(packet_hex 10.0.2.5 10.0.0.9 40000 22)
HEX_DEFAULT=$(packet_hex 8.8.8.8 1.1.1.1 12345 80)

echo "[policy] Checking policy deny overrides base allow..."
eval_expect "$HEX_POLICY_DENY" "Deny" "Policy deny overrides allow"

echo "[policy] Checking policy allow overrides base deny..."
eval_expect "$HEX_POLICY_ALLOW" "Allow" "Policy allow overrides default deny"

echo "[policy] Checking port deny overrides allow..."
eval_expect "$HEX_DENY_PORT" "Deny" "Port deny precedence"

echo "[policy] Checking port allow applies without policy..."
eval_expect "$HEX_ALLOW_PORT" "Allow" "Port allow"

echo "[policy] Checking default deny applies to unmatched traffic..."
eval_expect "$HEX_DEFAULT" "Deny" "Default deny"

echo "[policy] Checking conflicting CIDR rules are rejected..."
eval_expect_error "$CONFLICT_RULES_FILE" "$HEX_POLICY_DENY" "CIDR conflict detection" "conflicting CIDR rules overlap"

echo "[policy] Policy correctness checks passed."

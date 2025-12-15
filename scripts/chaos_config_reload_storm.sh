#!/usr/bin/env bash
# Chaos test: hammer rules file with rapid updates and reloads.
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
default deny ingress
RULES

echo "[chaos] Building release binary..."
cargo build -p aegis --release >/dev/null

BURST_SEC=${BURST_SEC:-10}       # how many seconds to hammer
UPDATE_RATE=${UPDATE_RATE:-5}    # updates per second (rule edits + reloads)

echo "[chaos] Running config reload storm for ${BURST_SEC}s at ${UPDATE_RATE}/s..."
END_TIME=$(( $(date +%s) + BURST_SEC ))
ITER=0

while [ "$(date +%s)" -lt "$END_TIME" ]; do
  ITER=$((ITER+1))
  # Rewrite rules file with varying CIDRs.
  python3 - "$RULES_FILE" "$ITER" <<'PY'
import sys, random
path=sys.argv[1]; it=int(sys.argv[2])
rng = random.Random(it)
with open(path,"w") as f:
    for i in range(100):
        octet = rng.randint(0,255)
        f.write(f"allow cidr 10.{octet}.0.0/16 ingress\n")
    f.write("deny port tcp 22 ingress\n")
    f.write("default deny ingress\n")
PY
  # Trigger a reload via list-rules (forces parse).
  ./target/release/aegis list-rules --rules "$RULES_FILE" >/dev/null
  # Small sleep to respect UPDATE_RATE
  sleep $(python3 - <<PY
rate=float("$UPDATE_RATE")
print(1.0/rate)
PY
)
done

echo "[chaos] Config reload storm finished (check logs/alerts for races)."

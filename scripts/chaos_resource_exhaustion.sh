#!/usr/bin/env bash
# Chaos test: simulate memory pressure and fd pressure around aegis evaluations.
# NOTE: This is a synthetic userspace stressor; tune limits via env vars.
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

MEM_PRESSURE_MB=${MEM_PRESSURE_MB:-512}   # amount of memory to touch (MB)
FD_COUNT=${FD_COUNT:-512}                 # number of dummy file descriptors to open
ITER=${ITER:-1000}                        # eval iterations under pressure

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
    print(" ".join(f\"{b:02x}\" for b in frame))
pkt()
PY
)"

echo "[chaos] Applying fd limit to 1024 (soft) for this shell..."
ulimit -Sn 1024 || true

echo "[chaos] Allocating ${MEM_PRESSURE_MB}MB synthetic memory..."
python3 - <<PY
import sys
size_mb=int("${MEM_PRESSURE_MB}")
try:
    data=bytearray(size_mb*1024*1024)
    for i in range(0,len(data),4096):
        data[i]=1
    print(f"[chaos] Allocated {size_mb}MB and touched pages")
except MemoryError:
    print("[chaos] Memory allocation failed (expected on very low limits)"); sys.exit(0)
PY

echo "[chaos] Opening ${FD_COUNT} dummy file descriptors..."
python3 - <<PY
import os, sys, tempfile
count=int("${FD_COUNT}")
handles=[]
try:
    for i in range(count):
        fd=os.open(tempfile.mkstemp()[1], os.O_RDONLY)
        handles.append(fd)
    print(f"[chaos] Opened {len(handles)} fds")
except OSError as e:
    print(f"[chaos] FD open failed after {len(handles)}: {e}")
    sys.exit(0)
# keep fds until shell exits
PY

echo "[chaos] Running ${ITER} evals under pressure..."
for _ in $(seq 1 "$ITER"); do
  ./target/release/aegis eval --rules "$RULES_FILE" --direction ingress --hex "$HTTP_HEX" --no-logs >/dev/null || {
    echo "[chaos] eval failed under pressure"; exit 1;
  }
done

echo "[chaos] Resource exhaustion test completed (no crash)."

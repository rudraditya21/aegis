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
unset AEGIS_CONFIG_READONLY
unset FIREWALL_CONFIG_READONLY
RULES_FILE="$FIREWALL_CONFIG_ROOT/rules.conf"
trap 'rm -rf "$CONFIG_ROOT"' EXIT

# Simple allow/deny rules for mixed traffic
cat >"$RULES_FILE" <<'RULES'
allow cidr 10.0.0.0/8 ingress
deny port tcp 22 ingress
default deny ingress
RULES

echo "[build] Building release binary..."
cargo build -p aegis --release >/dev/null

# Generate payloads
HTTP_HEX="$(
python3 - <<'PY'
import struct
def pkt(src_ip, dst_ip, sport, dport, payload):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H",0x0800)
    ver_ihl=(4<<4)|5
    total_len=20+20+len(payload)
    ip=struct.pack("!BBHHHBBHII",ver_ihl,0,total_len,1,0x4000,64,6,0,src_ip,dst_ip)
    tcp=struct.pack("!HHIIHHHH",sport,dport,1,0,(5<<12)|0x18,65535,0,0)
    frame=eth+ip+tcp+payload
    print(" ".join(f"{b:02x}" for b in frame))
pkt(0x0a000001,0x0a000002,12345,80,b"GET / HTTP/1.1\r\n")
PY
)"

SSH_HEX="$(
python3 - <<'PY'
import struct
def pkt(src_ip, dst_ip, sport, dport):
    eth=bytes.fromhex("ffe1e2e3e4e5001122334455")+struct.pack("!H",0x0800)
    ver_ihl=(4<<4)|5
    total_len=20+20
    ip=struct.pack("!BBHHHBBHII",ver_ihl,0,total_len,2,0x4000,64,6,0,src_ip,dst_ip)
    tcp=struct.pack("!HHIIHHHH",sport,dport,1,0,(5<<12)|0x02,65535,0,0)
    frame=eth+ip+tcp
    print(" ".join(f"{b:02x}" for b in frame))
pkt(0x0a000003,0x0a000004,55555,22)
PY
)"

UDP_HEX="$(
python3 - <<'PY'
import struct
def pkt(src_ip, dst_ip, sport, dport, payload):
    eth=bytes.fromhex("ffe1e2e3e4e5001122334455")+struct.pack("!H",0x0800)
    ver_ihl=(4<<4)|5
    total_len=20+8+len(payload)
    ip=struct.pack("!BBHHHBBHII",ver_ihl,0,total_len,3,0x4000,64,17,0,src_ip,dst_ip)
    udp=struct.pack("!HHHH",sport,dport,8+len(payload),0)
    frame=eth+ip+udp+payload
    print(" ".join(f"{b:02x}" for b in frame))
pkt(0x0a000005,0x0a000006,15000,53,b"\x00"*16)
PY
)"

bytes_per_frame=$(python3 - <<PY
http_hex = """$HTTP_HEX"""
frame_bytes = bytes.fromhex("".join(http_hex.split()))
print(len(frame_bytes))
PY
)

ALLOW_RUNS=${ALLOW_RUNS:-2000}
DENY_RUNS=${DENY_RUNS:-2000}
UDP_RUNS=${UDP_RUNS:-2000}
MIX_BATCH=${MIX_BATCH:-10000}

bench() {
  local label=$1 hex=$2 runs=$3 extra_flags=$4
  start_ns=$(date +%s%N)
  for _ in $(seq 1 "$runs"); do
    ./target/release/aegis eval --rules "$RULES_FILE" --direction ingress --hex "$hex" $extra_flags >/dev/null
  done
  end_ns=$(date +%s%N)
  elapsed_ns=$((end_ns - start_ns))
  python3 - <<PY
runs=$runs
elapsed=$elapsed_ns/1e9
pps=runs/elapsed
gbps=(pps*${bytes_per_frame}*8)/1e9
print(f"{label}: {pps:.2f} evals/sec ({gbps:.3f} Gbps payload-equivalent) over {runs} runs")
PY
}

echo "[throughput] TCP allow (stateless)..."
bench "TCP allow" "$HTTP_HEX" "$ALLOW_RUNS" "--no-logs --disable-ids --disable-ips"

echo "[throughput] TCP deny..."
bench "TCP deny" "$SSH_HEX" "$DENY_RUNS" "--no-logs --disable-ids --disable-ips"

echo "[throughput] UDP allow..."
bench "UDP allow" "$UDP_HEX" "$UDP_RUNS" "--no-logs --disable-ids --disable-ips"

echo "[throughput] Mixed batch via eval-batch (Rayon)..."
TMP_BATCH="$FIREWALL_CONFIG_ROOT/batch.hex"
rm -f "$TMP_BATCH"
for _ in $(seq 1 $((MIX_BATCH/2))); do echo "$HTTP_HEX" >> "$TMP_BATCH"; done
for _ in $(seq 1 $((MIX_BATCH/2))); do echo "$SSH_HEX" >> "$TMP_BATCH"; done
start_ns=$(date +%s%N)
./target/release/aegis eval-batch --rules "$RULES_FILE" --direction ingress --file "$TMP_BATCH" --no-logs --disable-ids --disable-ips >/dev/null
end_ns=$(date +%s%N)
elapsed_ns=$((end_ns - start_ns))
python3 - <<PY
runs=$MIX_BATCH
elapsed=$elapsed_ns/1e9
pps=runs/elapsed
gbps=(pps*${bytes_per_frame}*8)/1e9
print(f"Mixed eval-batch: {pps:.2f} packets/sec ({gbps:.3f} Gbps equiv) over {runs} packets")
PY

echo "[latency] Measuring eval latency (p50/p95/p99)..."
LAT_RUNS=${LAT_RUNS:-200}
python3 - <<'PY'
import subprocess, time, statistics, os
runs=int(os.environ.get("LAT_RUNS","200"))
cmd=["./target/release/aegis","eval","--rules",os.environ["RULES_FILE"],"--direction","ingress","--hex",os.environ["HTTP_HEX"],"--no-logs"]
dur=[]
for _ in range(runs):
    t0=time.perf_counter()
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    dur.append((time.perf_counter()-t0)*1000)
dur.sort()
def pct(p):
    idx=int(len(dur)*p)
    idx=max(0,min(idx,len(dur)-1))
    return dur[idx]
print(f"Latency ms: p50={pct(0.50):.3f} p95={pct(0.95):.3f} p99={pct(0.99):.3f} (stateless)")
PY
python3 - <<'PY'
import subprocess, time, statistics, os
runs=int(os.environ.get("LAT_RUNS","200"))
cmd=["./target/release/aegis","eval","--rules",os.environ["RULES_FILE"],"--direction","ingress","--hex",os.environ["HTTP_HEX"]]
dur=[]
for _ in range(runs):
    t0=time.perf_counter()
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    dur.append((time.perf_counter()-t0)*1000)
dur.sort()
def pct(p):
    idx=int(len(dur)*p)
    idx=max(0,min(idx,len(dur)-1))
    return dur[idx]
print(f"Latency ms: p50={pct(0.50):.3f} p95={pct(0.95):.3f} p99={pct(0.99):.3f} (stateful+DPI)")
PY

echo "[flow-scale] Loading many unique flows..."
FLOW_RUNS=${FLOW_RUNS:-50000}
start_ns=$(date +%s%N)
for i in $(seq 1 "$FLOW_RUNS"); do
  src=$((0x0a000000 + i))
  hex=$(python3 - "$src" <<'PY'
import struct, sys
src_ip=int(sys.argv[1])
eth=bytes.fromhex("ffe1e2e3e4e5001122334455")+struct.pack("!H",0x0800)
ver_ihl=(4<<4)|5
total_len=20+20
ip=struct.pack("!BBHHHBBHII",ver_ihl,0,total_len,10,0x4000,64,6,0,src_ip,0x0a0000ff)
tcp=struct.pack("!HHIIHHHH",40000,80,1,0,(5<<12)|0x10,65535,0,0)
frame=eth+ip+tcp
print(" ".join(f"{b:02x}" for b in frame))
PY
)
  ./target/release/aegis eval --rules "$RULES_FILE" --direction ingress --hex "$hex" --no-logs >/dev/null
done
end_ns=$(date +%s%N)
elapsed_ns=$((end_ns - start_ns))
python3 - <<PY
runs=$FLOW_RUNS
elapsed=$elapsed_ns/1e9
pps=runs/elapsed
print(f"Flow scale: {pps:.2f} flows/sec over {runs} unique flows")
PY

echo "[rule-scale] Generating 10k rules and timing load..."
RULE_SCALE=${RULE_SCALE:-10000}
RULE_SCALE_FILE="$FIREWALL_CONFIG_ROOT/rules_scale.conf"
python3 - "$RULE_SCALE_FILE" "$RULE_SCALE" <<'PY'
import sys
path=sys.argv[1]; n=int(sys.argv[2])
with open(path,"w") as f:
    for i in range(n):
        f.write(f"allow cidr 10.{i%255}.0.0/16 ingress\n")
    f.write("default deny ingress\n")
PY
start_ns=$(date +%s%N)
./target/release/aegis list-rules --rules "$RULE_SCALE_FILE" >/dev/null
end_ns=$(date +%s%N)
elapsed_ns=$((end_ns - start_ns))
python3 - <<PY
elapsed=$elapsed_ns/1e9
print(f"Rule scale load time: {elapsed:.3f}s for {int(${RULE_SCALE})} rules")
PY

echo "[external] Optional real-traffic generators (run when tools are installed):"
run_if_present() {
  local tool=$1; shift
  if command -v "$tool" >/dev/null 2>&1; then
    echo "[external] $tool $*"
    "$tool" "$@"
  else
    echo "[external] $tool not found; skipping"
  fi
}

# iperf3 TCP/UDP throughput (requires server running elsewhere)
if command -v iperf3 >/dev/null 2>&1; then
  IPERF_TARGET=${IPERF_TARGET:-127.0.0.1}
  echo "[external] iperf3 TCP to $IPERF_TARGET (10s)..."
  iperf3 -c "$IPERF_TARGET" -t 10 || true
  echo "[external] iperf3 UDP to $IPERF_TARGET (10s, 100M)..."
  iperf3 -u -b 100M -c "$IPERF_TARGET" -t 10 || true
else
  echo "[external] iperf3 not found; set IPERF_TARGET and install to run."
fi

# tcpreplay mixed pcap (set PCAP_FILE to your capture)
if command -v tcpreplay >/dev/null 2>&1 && [ -n "${PCAP_FILE:-}" ] && [ -f "$PCAP_FILE" ]; then
  echo "[external] tcpreplay on $PCAP_FILE ..."
  tcpreplay --quiet --intf1=lo "$PCAP_FILE" || true
else
  echo "[external] tcpreplay not run (set PCAP_FILE and ensure tcpreplay is installed)."
fi

# hping3 crafted packet flood (example SYN burst)
if command -v hping3 >/dev/null 2>&1; then
  HPING_TARGET=${HPING_TARGET:-127.0.0.1}
  echo "[external] hping3 SYN burst to $HPING_TARGET:80 (1s)..."
  hping3 -S -p 80 -i u1000 -c 1000 "$HPING_TARGET" >/dev/null 2>&1 || true
else
  echo "[external] hping3 not found; skipping."
fi

# wrk HTTP load (requires target HTTP endpoint)
if command -v wrk >/dev/null 2>&1 && [ -n "${WRK_URL:-}" ]; then
  echo "[external] wrk against $WRK_URL ..."
  wrk -t4 -c64 -d10s "${WRK_URL}" || true
else
  echo "[external] wrk not run (set WRK_URL and install wrk)."
fi

# dnsperf QPS (requires dnsperf and DNS server)
if command -v dnsperf >/dev/null 2>&1 && [ -n "${DNSPERF_SERVER:-}" ]; then
  echo "[external] dnsperf to $DNSPERF_SERVER (1k queries)..."
  printf "example.com. A\n" | dnsperf -s "$DNSPERF_SERVER" -d /dev/stdin -l 5 || true
else
  echo "[external] dnsperf not run (set DNSPERF_SERVER and install dnsperf)."
fi

# pktgen or pktgen-dpdk is environment-specific; print hint.
echo "[external] For line-rate PPS, run pktgen (kernel) or pktgen-dpdk with NIC binding on target host."

echo "[note] Perf/stress script finished. For full line-rate tests, run on NIC-attached hosts with pktgen/trex."

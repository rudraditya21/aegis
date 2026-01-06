#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_real_traffic_validation.sh [options]

Options:
  --iface <ifname>          Interface for tcpreplay.
  --pcap <file>             PCAP file to replay via tcpreplay.
  --tcpreplay-args <args>   Extra tcpreplay args (quoted).
  --iperf-server <host>     Run iperf3 client against server host.
  --iperf-time <seconds>    iperf3 duration (default: 10).
  --iperf-parallel <n>      iperf3 parallel streams (default: 1).
  --iperf-args <args>       Extra iperf3 args (quoted).
  --skip-tcpreplay          Skip tcpreplay even if --pcap is set.
  --skip-iperf              Skip iperf3 even if --iperf-server is set.
  -h, --help                Show help.

Examples:
  bash scripts/run_real_traffic_validation.sh --iface eth0 --pcap traces/traffic.pcap
  bash scripts/run_real_traffic_validation.sh --iperf-server 10.0.0.2 --iperf-time 30 --iperf-parallel 4
EOF
}

iface=""
pcap=""
tcpreplay_args=""
iperf_server=""
iperf_time=10
iperf_parallel=1
iperf_args=""
skip_tcpreplay=0
skip_iperf=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)
      iface="${2:-}"; shift 2 ;;
    --pcap)
      pcap="${2:-}"; shift 2 ;;
    --tcpreplay-args)
      tcpreplay_args="${2:-}"; shift 2 ;;
    --iperf-server)
      iperf_server="${2:-}"; shift 2 ;;
    --iperf-time)
      iperf_time="${2:-}"; shift 2 ;;
    --iperf-parallel)
      iperf_parallel="${2:-}"; shift 2 ;;
    --iperf-args)
      iperf_args="${2:-}"; shift 2 ;;
    --skip-tcpreplay)
      skip_tcpreplay=1; shift ;;
    --skip-iperf)
      skip_iperf=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -n "$pcap" && "$skip_tcpreplay" -eq 0 ]]; then
  if [[ -z "$iface" ]]; then
    echo "Missing --iface for tcpreplay" >&2
    exit 1
  fi
  if [[ ! -f "$pcap" ]]; then
    echo "PCAP not found: $pcap" >&2
    exit 1
  fi
  if ! command -v tcpreplay >/dev/null 2>&1; then
    echo "tcpreplay not found in PATH" >&2
    exit 1
  fi
  echo "[real-traffic] tcpreplay -> iface=$iface pcap=$pcap"
  tcpreplay --intf1 "$iface" $tcpreplay_args "$pcap"
else
  echo "[real-traffic] tcpreplay skipped"
fi

if [[ -n "$iperf_server" && "$skip_iperf" -eq 0 ]]; then
  if ! command -v iperf3 >/dev/null 2>&1; then
    echo "iperf3 not found in PATH" >&2
    exit 1
  fi
  echo "[real-traffic] iperf3 client -> server=$iperf_server time=${iperf_time}s parallel=$iperf_parallel"
  iperf3 -c "$iperf_server" -t "$iperf_time" -P "$iperf_parallel" $iperf_args
else
  echo "[real-traffic] iperf3 skipped"
fi

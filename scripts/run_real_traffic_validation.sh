#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_real_traffic_validation.sh [options]

Options:
  --mode <generator|server|both>
                          generator = tcpreplay + iperf client (default)
                          server    = iperf3 server only (one-shot)
                          both      = start server then run generator actions
  --iface <ifname>          Interface for tcpreplay.
  --pcap <file>             PCAP file to replay via tcpreplay.
  --tcpreplay-args <args>   Extra tcpreplay args (quoted).
  --iperf-server <host>     Run iperf3 client against server host.
  --iperf-port <port>       iperf3 server/client port (default: 5201).
  --iperf-time <seconds>    iperf3 duration (default: 10).
  --iperf-parallel <n>      iperf3 parallel streams (default: 1).
  --iperf-server-args <args>
                          Extra iperf3 server args (quoted).
  --iperf-args <args>       Extra iperf3 args (quoted).
  --iperf-server-persist    Keep server running (omit -1 one-shot).
  --skip-tcpreplay          Skip tcpreplay even if --pcap is set.
  --skip-iperf              Skip iperf3 even if --iperf-server is set.
  --dry-run                 Print commands without executing.
  -h, --help                Show help.

Examples:
  bash scripts/run_real_traffic_validation.sh --iface eth0 --pcap traces/traffic.pcap
  bash scripts/run_real_traffic_validation.sh --iperf-server 10.0.0.2 --iperf-time 30 --iperf-parallel 4
  bash scripts/run_real_traffic_validation.sh --mode server --iperf-port 5201
EOF
}

iface=""
pcap=""
mode="generator"
tcpreplay_args=""
iperf_server=""
iperf_port=5201
iperf_time=10
iperf_parallel=1
iperf_server_args=""
iperf_args=""
iperf_server_persist=0
skip_tcpreplay=0
skip_iperf=0
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      mode="${2:-}"; shift 2 ;;
    --iface)
      iface="${2:-}"; shift 2 ;;
    --pcap)
      pcap="${2:-}"; shift 2 ;;
    --tcpreplay-args)
      tcpreplay_args="${2:-}"; shift 2 ;;
    --iperf-server)
      iperf_server="${2:-}"; shift 2 ;;
    --iperf-port)
      iperf_port="${2:-}"; shift 2 ;;
    --iperf-time)
      iperf_time="${2:-}"; shift 2 ;;
    --iperf-parallel)
      iperf_parallel="${2:-}"; shift 2 ;;
    --iperf-server-args)
      iperf_server_args="${2:-}"; shift 2 ;;
    --iperf-args)
      iperf_args="${2:-}"; shift 2 ;;
    --iperf-server-persist)
      iperf_server_persist=1; shift ;;
    --skip-tcpreplay)
      skip_tcpreplay=1; shift ;;
    --skip-iperf)
      skip_iperf=1; shift ;;
    --dry-run)
      dry_run=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

case "$mode" in
  generator|server|both) ;;
  *)
    echo "Invalid --mode: $mode (expected generator|server|both)" >&2
    exit 1
    ;;
esac

run_server=0
run_generator=0
if [[ "$mode" == "server" ]]; then
  run_server=1
elif [[ "$mode" == "generator" ]]; then
  run_generator=1
else
  run_server=1
  run_generator=1
fi

run_cmd() {
  if [[ "$dry_run" -eq 1 ]]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

server_pid=""
if [[ "$run_server" -eq 1 && "$skip_iperf" -eq 0 ]]; then
  if ! command -v iperf3 >/dev/null 2>&1; then
    echo "iperf3 not found in PATH" >&2
    exit 1
  fi
  if [[ "$run_generator" -eq 1 ]]; then
    if [[ "$iperf_server_persist" -eq 1 ]]; then
      echo "[real-traffic] iperf3 server -> port=$iperf_port (persist, background)"
      if [[ "$dry_run" -eq 1 ]]; then
        echo "[dry-run] iperf3 -s -p \"$iperf_port\" $iperf_server_args &"
      else
        iperf3 -s -p "$iperf_port" $iperf_server_args &
        server_pid=$!
        sleep 1
      fi
    else
      echo "[real-traffic] iperf3 server -> port=$iperf_port (one-shot, background)"
      if [[ "$dry_run" -eq 1 ]]; then
        echo "[dry-run] iperf3 -s -1 -p \"$iperf_port\" $iperf_server_args &"
      else
        iperf3 -s -1 -p "$iperf_port" $iperf_server_args &
        server_pid=$!
        sleep 1
      fi
    fi
  else
    if [[ "$iperf_server_persist" -eq 1 ]]; then
      echo "[real-traffic] iperf3 server -> port=$iperf_port (persist)"
      run_cmd iperf3 -s -p "$iperf_port" $iperf_server_args
    else
      echo "[real-traffic] iperf3 server -> port=$iperf_port (one-shot)"
      run_cmd iperf3 -s -1 -p "$iperf_port" $iperf_server_args
    fi
  fi
elif [[ "$run_server" -eq 1 ]]; then
  echo "[real-traffic] iperf3 server skipped"
fi

if [[ "$run_generator" -eq 1 && -n "$pcap" && "$skip_tcpreplay" -eq 0 ]]; then
  if [[ -z "$iface" ]]; then
    echo "Missing --iface for tcpreplay" >&2
    exit 1
  fi
  if [[ ! -f "$pcap" ]]; then
    echo "PCAP not found: $pcap" >&2
    exit 1
  fi
  if [[ ${EUID} -ne 0 ]]; then
    echo "tcpreplay requires elevated privileges (run as root or with sudo)" >&2
    exit 1
  fi
  if ! command -v tcpreplay >/dev/null 2>&1; then
    echo "tcpreplay not found in PATH" >&2
    exit 1
  fi
  echo "[real-traffic] tcpreplay -> iface=$iface pcap=$pcap"
  run_cmd tcpreplay --intf1 "$iface" $tcpreplay_args "$pcap"
elif [[ "$run_generator" -eq 1 ]]; then
  echo "[real-traffic] tcpreplay skipped"
fi

if [[ "$run_generator" -eq 1 && -n "$iperf_server" && "$skip_iperf" -eq 0 ]]; then
  if ! command -v iperf3 >/dev/null 2>&1; then
    echo "iperf3 not found in PATH" >&2
    exit 1
  fi
  echo "[real-traffic] iperf3 client -> server=$iperf_server port=$iperf_port time=${iperf_time}s parallel=$iperf_parallel"
  run_cmd iperf3 -c "$iperf_server" -p "$iperf_port" -t "$iperf_time" -P "$iperf_parallel" $iperf_args
elif [[ "$run_generator" -eq 1 ]]; then
  echo "[real-traffic] iperf3 skipped"
fi

if [[ -n "$server_pid" ]]; then
  if [[ "$dry_run" -eq 1 ]]; then
    echo "[dry-run] wait $server_pid"
  else
    wait "$server_pid"
    if [[ "$iperf_server_persist" -eq 1 ]]; then
      echo "[real-traffic] iperf3 server stopped (persist mode)"
    fi
  fi
fi

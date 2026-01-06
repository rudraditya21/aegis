#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: docker/run_ci_tests.sh [pcap|af-xdp|dpdk|all]

Examples:
  docker/run_ci_tests.sh pcap
  docker/run_ci_tests.sh af-xdp
  docker/run_ci_tests.sh dpdk
  docker/run_ci_tests.sh all
EOF
}

FEATURES="${1:-pcap}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/target}"

run_feature() {
  local feature="$1"
  echo "[ci] feature set: ${feature}"

  cargo test -p aegis-core
  cargo test -p aegis-dataplane --features "${feature}"
  cargo test -p aegis --features "${feature}"

  case "${feature}" in
    af-xdp)
      cargo test -p aegis-af-xdp
      ;;
    dpdk)
      cargo test -p aegis-dpdk --features dpdk
      ;;
  esac
}

case "${FEATURES}" in
  pcap|af-xdp|dpdk)
    run_feature "${FEATURES}"
    ;;
  all)
    run_feature pcap
    run_feature af-xdp
    run_feature dpdk
    ;;
  *)
    usage
    exit 2
    ;;
esac

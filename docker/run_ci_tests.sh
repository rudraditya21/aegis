#!/usr/bin/env bash
set -euo pipefail

FEATURES="${1:-pcap}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/target}"

echo "[ci] feature set: ${FEATURES}"

cargo test -p aegis-core
cargo test -p aegis-dataplane --features "${FEATURES}"
cargo test -p aegis --features "${FEATURES}"

case "${FEATURES}" in
  af-xdp)
    cargo test -p aegis-af-xdp
    ;;
  dpdk)
    cargo test -p aegis-dpdk --features dpdk
    ;;
esac

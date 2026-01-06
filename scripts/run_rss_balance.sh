#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

FLOWS=${RSS_FLOWS:-200000}
WORKERS=${RSS_WORKERS:-4}
PROTO=${RSS_PROTO:-tcp}
IPV6=${RSS_IPV6:-0}

args=(--flows "$FLOWS" --workers "$WORKERS" --protocol "$PROTO")
if [ "$IPV6" = "1" ]; then
  args+=(--ipv6)
fi

echo "[rss-balance] flows=$FLOWS workers=$WORKERS protocol=$PROTO ipv6=$IPV6"
cargo run -p aegis -- rss-balance "${args[@]}"

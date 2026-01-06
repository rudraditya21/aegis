#!/usr/bin/env bash
# Run full test battery: unit tests, CLI checks, attack sims, feature matrix.
set -euo pipefail
cd -- "$(dirname "$0")/.."

echo "[all] Running cargo test..."
cargo test

echo "[all] Running CLI checks..."
bash scripts/run_cli_checks.sh

echo "[all] Running attack simulations..."
for f in \
  scripts/attack_syn_flood.sh \
  scripts/attack_tcp_ack_flood.sh \
  scripts/attack_udp_flood.sh \
  scripts/attack_icmp_flood.sh \
  scripts/attack_fragmentation.sh \
  scripts/attack_dns_amplification.sh \
  scripts/attack_http_flood.sh \
  scripts/attack_slowloris.sh \
  scripts/attack_http_obfuscation.sh \
  scripts/attack_unicode_encoding.sh \
  scripts/attack_tls_handshake_flood.sh \
  scripts/attack_fragmented_tls_clienthello.sh \
  scripts/attack_tcp_segmentation.sh \
  scripts/attack_protocol_confusion.sh \
  scripts/attack_exploit_signatures.sh \
  scripts/attack_c2_beacon.sh
do
  echo "[all] Running $f ..."
  bash "$f"
done

echo "[all] Running feature matrix..."
bash scripts/run_feature_matrix.sh

echo "[all] Running RSS balance benchmark..."
bash scripts/run_rss_balance.sh

echo "[all] (Optional) Perf/stress tests: run scripts/run_perf_stress.sh manually if needed."
echo "[all] Complete."

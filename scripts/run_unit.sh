#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

echo "Running Rust unit/regression tests..."
cargo test --all

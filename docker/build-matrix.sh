#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_PREFIX="${IMAGE_PREFIX:-aegis}"
CARGO_FEATURES="${CARGO_FEATURES:-pcap}"
BUILD_PROFILE="${BUILD_PROFILE:-release}"

RUNTIME_BASES=(
  "debian:bookworm-slim"
  "ubuntu:22.04"
  "fedora:40"
)

TAGS=(
  "debian"
  "ubuntu2204"
  "fedora40"
)

for idx in "${!RUNTIME_BASES[@]}"; do
  base="${RUNTIME_BASES[$idx]}"
  tag="${TAGS[$idx]}"
  echo "Building ${IMAGE_PREFIX}:${tag} (base=${base})"
  docker build \
    -f "${ROOT}/docker/Dockerfile.runtime" \
    --build-arg "RUNTIME_BASE=${base}" \
    --build-arg "CARGO_FEATURES=${CARGO_FEATURES}" \
    --build-arg "BUILD_PROFILE=${BUILD_PROFILE}" \
    -t "${IMAGE_PREFIX}:${tag}" \
    "${ROOT}"
done

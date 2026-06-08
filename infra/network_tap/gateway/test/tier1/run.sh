#!/usr/bin/env bash
# Tier 1 -- Rust build/compile + algorithmic validation (cargo check && cargo test)
# Usage: ./test/tier1/run.sh [--no-cache]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_TAG="network-tap-gateway-tier1:latest"
NO_CACHE=""

for arg in "$@"; do
    [ "$arg" = "--no-cache" ] && NO_CACHE="--no-cache"
done

ENGINE="docker"
command -v docker >/dev/null 2>&1 || ENGINE="podman"
if ! command -v "$ENGINE" >/dev/null 2>&1; then
    echo "ERROR: neither docker nor podman found -- cannot run containerized build check."
    exit 1
fi

echo "[tier1] Building cargo check+test image ($ENGINE, context=$GATEWAY_DIR)..."
"$ENGINE" build $NO_CACHE -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE_TAG" "$GATEWAY_DIR"

echo "[tier1] Running 'cargo check && cargo test --lib' inside container..."
"$ENGINE" run --rm "$IMAGE_TAG"

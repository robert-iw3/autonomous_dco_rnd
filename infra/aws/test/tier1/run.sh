#!/usr/bin/env bash
# Tier 1 -- Rust build/compile validation (cargo check x3 crates)
# Usage: ./test/tier1/run.sh [--no-cache]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AWS_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_TAG="nexus-aws-connectors-tier1:latest"
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

echo "[tier1] Building cargo-check image ($ENGINE, context=$AWS_DIR)..."
"$ENGINE" build $NO_CACHE -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE_TAG" "$AWS_DIR"

echo "[tier1] Running 'cargo check' for vpc, cloudtrail, guardduty inside container..."
"$ENGINE" run --rm "$IMAGE_TAG"

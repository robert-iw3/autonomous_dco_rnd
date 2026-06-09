#!/usr/bin/env bash
# Tier 2 -- deploy/ IaC validation (runtime-contract + posture + convergence)
# Usage: ./test/tier2/run.sh [--no-cache]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AZURE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_TAG="nexus-azure-connectors-tier2:latest"
NO_CACHE=""

for arg in "$@"; do
    [ "$arg" = "--no-cache" ] && NO_CACHE="--no-cache"
done

ENGINE="docker"
command -v docker >/dev/null 2>&1 || ENGINE="podman"
if ! command -v "$ENGINE" >/dev/null 2>&1; then
    echo "ERROR: neither docker nor podman found -- cannot run containerized IaC checks."
    exit 1
fi

echo "[tier2] Building IaC-validation image ($ENGINE, context=$AZURE_DIR)..."
"$ENGINE" build $NO_CACHE -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE_TAG" "$AZURE_DIR"

echo "[tier2] Running deploy/ IaC validation (terraform + scanners) inside container..."
"$ENGINE" run --rm "$IMAGE_TAG"

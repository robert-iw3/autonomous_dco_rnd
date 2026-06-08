#!/usr/bin/env bash
# Tier 1 -- Rust build/compile + algorithmic validation (cargo check && cargo test)
# Usage: ./test/tier1/run.sh [--no-cache]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
IMAGE_TAG="linux-sentinel-tier1:latest"
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

echo "[tier1] Building cargo check+test image ($ENGINE, context=$REPO_ROOT)..."
"$ENGINE" build $NO_CACHE -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE_TAG" "$REPO_ROOT"

BTF_MOUNT=()
if [ -r /sys/kernel/btf/vmlinux ]; then
    BTF_MOUNT=(-v /sys/kernel/btf:/sys/kernel/btf:ro)
else
    echo "[tier1] WARNING: /sys/kernel/btf/vmlinux not readable on host -- BPF object build will fall back to the generic staged vmlinux.h and may fail to compile."
fi

echo "[tier1] Running 'cargo check && cargo test' inside container..."
"$ENGINE" run --rm "${BTF_MOUNT[@]}" "$IMAGE_TAG"
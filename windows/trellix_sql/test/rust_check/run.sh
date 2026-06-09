#!/usr/bin/env bash
# Run the core_ingress Rust compilation check inside a container.
# Verifies that the transmit-layer receiver (sensor_middleware/core_ingress)
# compiles cleanly with cargo check, ensuring the HMAC receiver interface
# does not bit-rot independently of the Python transmit layer.
#
# Usage:
#   ./run.sh              # normal run
#   ./run.sh --no-cache   # force full rebuild (re-downloads all crates)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WINDOWS_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/../reports"
IMAGE_TAG="nexus-core-ingress-rust-check:latest"

ENGINE="docker"
command -v docker >/dev/null 2>&1 || ENGINE="podman"

BUILD_ARGS=()
if [[ "${1:-}" == "--no-cache" ]]; then
    BUILD_ARGS+=("--no-cache")
fi

echo "[rust_check] Build context : ${WINDOWS_DIR}"
echo "[rust_check] Container engine: ${ENGINE}"
echo "[rust_check] Building image ${IMAGE_TAG}..."

"${ENGINE}" build "${BUILD_ARGS[@]}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    -t "${IMAGE_TAG}" \
    "${WINDOWS_DIR}"

mkdir -p "${REPORTS_DIR}"

echo "[rust_check] Running cargo check..."
RESULT=0
"${ENGINE}" run --rm "${IMAGE_TAG}" || RESULT=$?

if [[ ${RESULT} -eq 0 ]]; then
    echo "[rust_check] PASSED — core_ingress compiles cleanly"
    echo "PASSED" > "${REPORTS_DIR}/rust_check_result.txt"
else
    echo "[rust_check] FAILED — see cargo output above"
    echo "FAILED" > "${REPORTS_DIR}/rust_check_result.txt"
    exit 1
fi
#!/usr/bin/env bash
# Run the trellix_sql tier2 Python+SQLite test suite inside a container.
# Reports are written to windows/trellix_sql/test/reports/ on the host.
#
# Usage:
#   ./run.sh              # normal run
#   ./run.sh --no-cache   # force full image rebuild
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRELLIX_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPORTS_DIR="${TRELLIX_DIR}/test/reports"
IMAGE_TAG="nexus-trellix-sql-tier2:latest"

ENGINE="docker"
command -v docker >/dev/null 2>&1 || ENGINE="podman"

BUILD_ARGS=()
if [[ "${1:-}" == "--no-cache" ]]; then
    BUILD_ARGS+=("--no-cache")
fi

echo "[tier2] Build context : ${TRELLIX_DIR}"
echo "[tier2] Container engine: ${ENGINE}"
echo "[tier2] Building image ${IMAGE_TAG}..."
"${ENGINE}" build "${BUILD_ARGS[@]}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    -t "${IMAGE_TAG}" \
    "${TRELLIX_DIR}"

mkdir -p "${REPORTS_DIR}"

echo "[tier2] Running pytest..."
"${ENGINE}" run --rm \
    -v "${REPORTS_DIR}:/reports:Z" \
    "${IMAGE_TAG}"

echo "[tier2] Reports: ${REPORTS_DIR}/tier2_report.xml"
echo "[tier2]          ${REPORTS_DIR}/tier2_report.json"
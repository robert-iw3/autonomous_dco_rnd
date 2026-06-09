#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
IMAGE="vmware-connector-tier2:$(date +%s)"

echo "==> Building tier2 image..."
docker build \
  --file "${REPO_ROOT}/infra/vmware/test/tier2/Dockerfile" \
  --tag  "${IMAGE}" \
  "${REPO_ROOT}"

echo "==> Running tier2 tests..."
docker run --rm "${IMAGE}"

echo "==> Cleaning up image..."
docker rmi "${IMAGE}" --force >/dev/null 2>&1 || true
echo "==> tier2 complete"
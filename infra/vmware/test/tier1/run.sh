#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
IMAGE="vmware-connector-tier1:$(date +%s)"

echo "==> Building tier1 image (cargo check)..."
docker build \
  --file "${REPO_ROOT}/infra/vmware/test/tier1/Dockerfile" \
  --tag  "${IMAGE}" \
  "${REPO_ROOT}"

echo "==> cargo check passed"
docker rmi "${IMAGE}" --force >/dev/null 2>&1 || true
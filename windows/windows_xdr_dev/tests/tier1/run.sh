#!/usr/bin/env bash
# Tier 1 — Rust workspace validator
# Usage: ./tests/tier1/run.sh [--no-cache] [--push-image]
# Must be run from the windows/windows_xdr_dev/ repo root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_TAG="deepxdr-tier1:latest"
CONTAINER_NAME="deepxdr_tier1_$$"
REPORT_DIR="$REPO_ROOT/tests/reports"
LOGFILE="$REPORT_DIR/tier1_rust.log"
NO_CACHE=""

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --no-cache) NO_CACHE="--no-cache" ;;
        --help|-h)
            echo "Usage: $0 [--no-cache]"
            echo "  --no-cache   Force full Docker layer rebuild (skip layer cache)"
            exit 0
            ;;
    esac
done

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$REPORT_DIR"

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  DeepXDR Tier 1 — Rust Workspace Validation      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo "   Context: $REPO_ROOT"
echo "   Image:   $IMAGE_TAG"
echo "   Log:     $LOGFILE"
echo ""

# Preflight: docker must be available
if ! command -v docker &>/dev/null; then
    echo -e "${RED}ERROR: docker not found. Install Docker Desktop or Docker Engine.${NC}"
    exit 1
fi

START=$(date +%s)

echo -e "${YELLOW}[1/2] Building Docker image (cargo check + test + clippy)...${NC}"
docker build \
    $NO_CACHE \
    --progress=plain \
    -f "$SCRIPT_DIR/Dockerfile" \
    -t "$IMAGE_TAG" \
    "$REPO_ROOT" \
    2>&1 | tee "$LOGFILE"

BUILD_RC=${PIPESTATUS[0]}
END=$(date +%s)
ELAPSED=$((END - START))

echo ""
if [ "$BUILD_RC" -eq 0 ]; then
    echo -e "${GREEN}✔  Tier 1 PASSED  (${ELAPSED}s)${NC}"
    echo "   Full log: $LOGFILE"
    exit 0
else
    echo -e "${RED}✘  Tier 1 FAILED  (${ELAPSED}s)${NC}"
    echo "   Full log: $LOGFILE"
    echo ""
    echo -e "${YELLOW}Last 40 lines of output:${NC}"
    tail -40 "$LOGFILE"
    exit 1
fi

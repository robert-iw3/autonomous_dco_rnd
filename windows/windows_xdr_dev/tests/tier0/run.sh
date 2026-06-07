#!/usr/bin/env bash
# Tier 0 - Python logic tests (Alpine container)
# Usage: ./tests/tier0/run.sh [--no-cache] [--html] [--keep]
# Must be run from the windows/windows_xdr_dev/ repo root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_TAG="deepxdr-tier0:latest"
REPORT_DIR="$REPO_ROOT/tests/reports"
LOGFILE="$REPORT_DIR/tier0_python.log"
NO_CACHE=""
HTML_FLAG=""
KEEP_CONTAINER=false

for arg in "$@"; do
    case "$arg" in
        --no-cache)  NO_CACHE="--no-cache" ;;
        --html)      HTML_FLAG="--html=/app/tests/reports/tier0_report.html --self-contained-html" ;;
        --keep)      KEEP_CONTAINER=true ;;
        --help|-h)
            echo "Usage: $0 [--no-cache] [--html] [--keep]"
            echo "  --no-cache   Force full Docker layer rebuild"
            echo "  --html       Generate HTML test report in tests/reports/"
            echo "  --keep       Keep container after run (for debugging)"
            exit 0
            ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$REPORT_DIR"

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  DeepXDR Tier 0 - Python Logic Tests (Alpine)    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo "   Context: $REPO_ROOT"
echo "   Image:   $IMAGE_TAG"
echo "   Log:     $LOGFILE"
echo ""

if ! command -v docker &>/dev/null; then
    echo -e "${RED}ERROR: docker not found.${NC}"
    exit 1
fi

START=$(date +%s)

# Build image
echo -e "${YELLOW}[1/2] Building Alpine image with Python test suite...${NC}"
docker build \
    $NO_CACHE \
    --progress=plain \
    -f "$SCRIPT_DIR/Dockerfile" \
    -t "$IMAGE_TAG" \
    "$REPO_ROOT" \
    2>&1 | tee "$LOGFILE"

BUILD_RC=${PIPESTATUS[0]}
if [ "$BUILD_RC" -ne 0 ]; then
    echo -e "${RED}✘  Docker build failed - check $LOGFILE${NC}"
    exit 1
fi

# Run tests inside container
echo ""
echo -e "${YELLOW}[2/2] Running pytest inside container...${NC}"

REMOVE_FLAG="--rm"
$KEEP_CONTAINER && REMOVE_FLAG=""

docker run \
    $REMOVE_FLAG \
    --name "deepxdr_tier0_$$" \
    -v "$REPORT_DIR:/app/tests/reports" \
    "$IMAGE_TAG" \
    python3 -m pytest \
        tests/tier0 \
        tests/tier4 \
        -v \
        --tb=short \
        --color=yes \
        --cov=tests/tier0 \
        --cov-report=term-missing \
        --cov-report="html:/app/tests/reports/tier0_coverage" \
        $HTML_FLAG \
    2>&1 | tee -a "$LOGFILE"

RUN_RC=${PIPESTATUS[0]}
END=$(date +%s)
ELAPSED=$((END - START))

echo ""
if [ "$RUN_RC" -eq 0 ]; then
    echo -e "${GREEN}✔  Tier 0 PASSED  (${ELAPSED}s)${NC}"
    echo "   Coverage HTML: $REPORT_DIR/tier0_coverage/index.html"
    exit 0
else
    echo -e "${RED}✘  Tier 0 FAILED  (${ELAPSED}s) - see $LOGFILE${NC}"
    exit 1
fi

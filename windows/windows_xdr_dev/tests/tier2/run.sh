#!/usr/bin/env bash
# Tier 2 — .NET 10 cross-compile validator
# Usage: ./tests/tier2/run.sh [--no-cache]
# Must be run from the windows/windows_xdr_dev/ repo root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_TAG="deepxdr-tier2:latest"
REPORT_DIR="$REPO_ROOT/tests/reports"
LOGFILE="$REPORT_DIR/tier2_dotnet.log"
NO_CACHE=""

for arg in "$@"; do
    case "$arg" in
        --no-cache) NO_CACHE="--no-cache" ;;
        --help|-h)
            echo "Usage: $0 [--no-cache]"
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
echo -e "${CYAN}║  DeepXDR Tier 2 — .NET 10 Cross-Compile Check    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo "   Context: $REPO_ROOT"
echo "   Image:   $IMAGE_TAG"
echo "   Log:     $LOGFILE"
echo ""
echo -e "${YELLOW}NOTE: Linux cannot link Windows-only APIs (ETW/SCM/NDIS).${NC}"
echo -e "${YELLOW}      P/Invoke and PlatformNotSupportedException linker errors are${NC}"
echo -e "${YELLOW}      expected. All C# syntax/type errors require fixes.${NC}"
echo ""

if ! command -v docker &>/dev/null; then
    echo -e "${RED}ERROR: docker not found.${NC}"
    exit 1
fi

START=$(date +%s)

echo -e "${YELLOW}[1/2] Building Docker image...${NC}"
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

# Parse the log to extract error/warning counts
ERRORS=$(grep -c "error CS" "$LOGFILE" 2>/dev/null || true)
WARNINGS=$(grep -c "warning CS" "$LOGFILE" 2>/dev/null || true)

echo ""
echo "   C# errors:   $ERRORS"
echo "   C# warnings: $WARNINGS"
echo ""

# Tier 2 exit: pass if image built (even with expected Windows link errors)
# A non-zero BUILD_RC here means unexpected failure (package not found, etc.)
if [ "$BUILD_RC" -eq 0 ]; then
    echo -e "${GREEN}✔  Tier 2 PASSED  (${ELAPSED}s)${NC}"
    exit 0
else
    echo -e "${RED}✘  Tier 2 FAILED  (${ELAPSED}s) — see $LOGFILE${NC}"
    echo ""
    echo -e "${YELLOW}Last 50 lines:${NC}"
    tail -50 "$LOGFILE"
    exit 1
fi

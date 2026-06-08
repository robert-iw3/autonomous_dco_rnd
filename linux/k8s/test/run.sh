#!/usr/bin/env bash
# falco_transmitter (k8s) Test Workbench
# ===============================================================================
# Tier 0 - Schema-contract + transmission-layer conformance (pytest, no containers)
# Tier 1 - Rust build/compile validation (cargo check && cargo test, containerized)
#
# Usage:
#   ./test/run.sh              # Tier 0 only (fast, no Docker/Podman needed)
#   ./test/run.sh --all        # Tier 0 + Tier 1
#   ./test/run.sh --tier 0
#   ./test/run.sh --tier 1
# ===============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_TIER0=true
RUN_TIER1=false

for arg in "$@"; do
    case "$arg" in
        --all) RUN_TIER1=true ;;
    esac
done
if [ "${1:-}" = "--tier" ]; then
    case "${2:-}" in
        0) RUN_TIER0=true;  RUN_TIER1=false ;;
        1) RUN_TIER0=false; RUN_TIER1=true ;;
    esac
fi

OVERALL=0

if $RUN_TIER0; then
    echo "=== Tier 0: schema-contract + transmission-layer tests (pytest) ==="
    python3 -m pytest "$SCRIPT_DIR/tier0" -v --tb=short -p no:cacheprovider || OVERALL=1
fi

if $RUN_TIER1; then
    echo ""
    echo "=== Tier 1: Rust build/compile validation (cargo check && cargo test) ==="
    bash "$SCRIPT_DIR/tier1/run.sh" || OVERALL=1
fi

exit $OVERALL

#!/usr/bin/env bash
# VMware connector test orchestrator.
# Usage:
#   ./run.sh           -- run tier0 only (pure Python, no containers)
#   ./run.sh --all     -- run tier0 + tier1 + tier2
#   ./run.sh --tier 0  -- run specific tier(s)
#   ./run.sh --tier 1
#   ./run.sh --tier 2
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

TIERS=()

usage() {
    sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)         TIERS=(0 1 2); shift ;;
        --tier)        TIERS+=("$2"); shift 2 ;;
        -h|--help)     usage ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
done

[[ ${#TIERS[@]} -eq 0 ]] && TIERS=(0)

run_tier0() {
    echo "===== Tier0: pure Python (schema / transmission) ====="
    python3 -m pytest -v "${SCRIPT_DIR}/tier0/" --tb=short
}

run_tier1() {
    echo "===== Tier1: cargo check ====="
    chmod +x "${SCRIPT_DIR}/tier1/run.sh"
    bash "${SCRIPT_DIR}/tier1/run.sh"
}

run_tier2() {
    echo "===== Tier2: IaC convergence / posture / runtime contract ====="
    chmod +x "${SCRIPT_DIR}/tier2/run.sh"
    bash "${SCRIPT_DIR}/tier2/run.sh"
}

for tier in "${TIERS[@]}"; do
    case "$tier" in
        0) run_tier0 ;;
        1) run_tier1 ;;
        2) run_tier2 ;;
        *) echo "Unknown tier: $tier"; exit 1 ;;
    esac
done

echo "===== All selected tiers passed ====="
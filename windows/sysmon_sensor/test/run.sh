#!/usr/bin/env bash
# sysmon_sensor Test Workbench
# ===============================================================================
# Usage:
#   ./test/run.sh
# ===============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Tier 0: algorithm, data-contract & transmission-layer tests (pytest) ==="
python3 -m pytest "$SCRIPT_DIR/tier0" -v --tb=short -p no:cacheprovider
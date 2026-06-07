#!/usr/bin/env bash
# DeepXDR Automated Test Workbench
# ===============================================================================
# Entry point for the full regression suite.
#
# Tier 0 - Python logic tests (always runs, no containers needed)
# Tier 1 - Rust workspace: cargo check + test + clippy (requires Docker)
# Tier 2 - .NET cross-compile: dotnet restore + build win-x64 (requires Docker)
# Tier 3 - Windows smoke tests (requires Windows VM + PowerShell - manual)
# Tier 4a- Driver contract tests (runs with Tier 0 in Python; no Docker)
#
# Usage:
#   ./tests/run_workbench.sh              # Tier 0 + 4a only (fastest, no Docker)
#   ./tests/run_workbench.sh --all        # Tier 0 + 1 + 2 + 4a (requires Docker)
#   ./tests/run_workbench.sh --tier 0     # Specific tier
#   ./tests/run_workbench.sh --tier 1     # Rust only
#   ./tests/run_workbench.sh --tier 2     # .NET only
#   ./tests/run_workbench.sh --no-cache   # Force Docker layer rebuild
#   ./tests/run_workbench.sh --html       # Generate HTML report
#
# Exit codes:
#   0  All executed tiers passed
#   1  One or more tiers failed
#   2  Usage / preflight error
# ===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$SCRIPT_DIR/reports"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
MASTER_LOG="$REPORT_DIR/workbench_$TIMESTAMP.log"

# --- Flags --------------------------------------------------------------------

RUN_TIER0=true
RUN_TIER1=false
RUN_TIER2=false
RUN_TIER4=true
NO_CACHE=""
HTML_REPORT=false
SPECIFIC_TIER=""
FAIL_FAST=false

for arg in "$@"; do
    case "$arg" in
        --all)      RUN_TIER1=true; RUN_TIER2=true ;;
        --no-cache) NO_CACHE="--no-cache" ;;
        --html)     HTML_REPORT=true ;;
        --fail-fast|-x) FAIL_FAST=true ;;
        --tier)     ;;  # handled with shift below
        -h|--help)
            sed -n '/^# Usage/,/^# Exit/p' "$0" | sed 's/^# //'
            exit 0
            ;;
    esac
done

# Handle --tier N
for i in $(seq 1 $#); do
    if [ "${!i}" = "--tier" ]; then
        j=$((i+1))
        SPECIFIC_TIER="${!j:-}"
        case "$SPECIFIC_TIER" in
            0)  RUN_TIER0=true;  RUN_TIER1=false; RUN_TIER2=false; RUN_TIER4=false ;;
            1)  RUN_TIER0=false; RUN_TIER1=true;  RUN_TIER2=false; RUN_TIER4=false ;;
            2)  RUN_TIER0=false; RUN_TIER1=false; RUN_TIER2=true;  RUN_TIER4=false ;;
            4)  RUN_TIER0=false; RUN_TIER1=false; RUN_TIER2=false; RUN_TIER4=true  ;;
            *) echo "ERROR: Unknown tier: $SPECIFIC_TIER"; exit 2 ;;
        esac
    fi
done

# --- Colors -------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# --- Tracking -----------------------------------------------------------------

declare -A TIER_STATUS   # "PASS" | "FAIL" | "SKIP"
declare -A TIER_ELAPSED  # seconds
OVERALL_PASS=true

mkdir -p "$REPORT_DIR"

# --- Helpers ------------------------------------------------------------------

log() {
    local msg="$1"
    echo -e "$msg" | tee -a "$MASTER_LOG"
}

banner() {
    log ""
    log "${CYAN}╔==============================================================╗${NC}"
    log "${CYAN}║  ${BOLD}$1${NC}${CYAN}$(printf '%*s' $((62 - ${#1} - 2)) '')║${NC}"
    log "${CYAN}╚==============================================================╝${NC}"
}

run_tier() {
    local tier_name="$1"
    local tier_key="$2"
    shift 2
    local cmd=("$@")

    log ""
    log "${CYAN}┌-[ ${BOLD}$tier_name${NC}${CYAN} ]-------------------------------------------------${NC}"

    local start
    start=$(date +%s)

    if "${cmd[@]}" 2>&1 | tee -a "$MASTER_LOG"; then
        local elapsed=$(( $(date +%s) - start ))
        TIER_STATUS["$tier_key"]="PASS"
        TIER_ELAPSED["$tier_key"]="$elapsed"
        log "${GREEN}└- PASSED (${elapsed}s)${NC}"
    else
        local elapsed=$(( $(date +%s) - start ))
        TIER_STATUS["$tier_key"]="FAIL"
        TIER_ELAPSED["$tier_key"]="$elapsed"
        OVERALL_PASS=false
        log "${RED}└- FAILED (${elapsed}s)${NC}"
        if $FAIL_FAST; then
            log "${RED}Fail-fast enabled - aborting.${NC}"
            print_summary
            exit 1
        fi
    fi
}

skip_tier() {
    local tier_name="$1"
    local tier_key="$2"
    local reason="$3"
    TIER_STATUS["$tier_key"]="SKIP"
    TIER_ELAPSED["$tier_key"]="0"
    log ""
    log "${YELLOW}[ SKIP ] $tier_name - $reason${NC}"
}

# --- Preflight checks ---------------------------------------------------------

preflight() {
    log ""
    log "${BOLD}Preflight checks...${NC}"

    # All tiers run inside Docker containers (Alpine for Python, custom for Rust/.NET)
    if command -v docker &>/dev/null; then
        DOCKER_VER=$(docker --version 2>&1)
        log "  docker:   $DOCKER_VER"
        DOCKER_OK=true
    else
        log "${RED}ERROR: docker not found. All tiers require Docker.${NC}"
        log "${RED}       Install Docker Desktop or Docker Engine and re-run.${NC}"
        exit 2
    fi

    log ""
}

# --- Summary printer ----------------------------------------------------------

print_summary() {
    log ""
    log "${MAGENTA}╔==============================================================╗${NC}"
    log "${MAGENTA}║  ${BOLD}DeepXDR Workbench Summary${NC}${MAGENTA}                                    ║${NC}"
    log "${MAGENTA}╠==============================================================╣${NC}"

    local order=("T0" "T1" "T2" "T4")
    local labels=("Tier 0 - Python logic tests  " "Tier 1 - Rust workspace      " "Tier 2 - .NET cross-compile  " "Tier 4a- Driver contracts    ")
    for i in "${!order[@]}"; do
        local key="${order[$i]}"
        local label="${labels[$i]}"
        local status="${TIER_STATUS[$key]:-SKIP}"
        local elapsed="${TIER_ELAPSED[$key]:-0}"

        case "$status" in
            PASS) log "${MAGENTA}║  ${GREEN}PASS${MAGENTA}  $label ${elapsed}s          ║${NC}" ;;
            FAIL) log "${MAGENTA}║  ${RED}FAIL${MAGENTA}  $label ${elapsed}s          ║${NC}" ;;
            SKIP) log "${MAGENTA}║  ${YELLOW}SKIP${MAGENTA}  $label -                 ║${NC}" ;;
        esac
    done

    log "${MAGENTA}╠==============================================================╣${NC}"

    if $OVERALL_PASS; then
        log "${MAGENTA}║  ${GREEN}${BOLD}OVERALL: ALL EXECUTED TIERS PASSED${NC}${MAGENTA}                        ║${NC}"
    else
        log "${MAGENTA}║  ${RED}${BOLD}OVERALL: ONE OR MORE TIERS FAILED${NC}${MAGENTA}                         ║${NC}"
    fi

    log "${MAGENTA}╚==============================================================╝${NC}"
    log ""
    log "   Master log: $MASTER_LOG"
    log "   Reports:    $REPORT_DIR"
    log ""

    if [ -n "${HTML_PATH:-}" ]; then
        log "   HTML report: $HTML_PATH"
        log ""
    fi

    # Tier 3 reminder
    log "${YELLOW}   Tier 3 (Windows smoke tests) requires a Windows 11 VM.${NC}"
    log "${YELLOW}   Run: tests/tier3/Invoke-SmokeTests.ps1 on the test machine.${NC}"
    log ""
}

# --- Main execution -----------------------------------------------------------

banner "DeepXDR Automated Test Workbench"
log "   Timestamp: $TIMESTAMP"
log "   Repo:      $REPO_ROOT"
log "   Log:       $MASTER_LOG"

preflight

# --- Tier 0 + 4a: Python tests in Alpine container ----------------------------
# tier0/run.sh builds an Alpine 3.23 image and runs pytest for both
# tests/tier0 and tests/tier4 in a single containerised pass.

if $RUN_TIER0 || $RUN_TIER4; then
    T0_FLAGS=""
    $HTML_REPORT && T0_FLAGS="$T0_FLAGS --html" || true
    [ -n "$NO_CACHE" ] && T0_FLAGS="$T0_FLAGS --no-cache" || true

    run_tier "Tier 0+4a - Python & driver contracts (Alpine 3.23)" "T0" \
        bash "$SCRIPT_DIR/tier0/run.sh" $T0_FLAGS

    # Mirror result to T4 key (both run in the same container pass)
    TIER_STATUS["T4"]="${TIER_STATUS["T0"]:-SKIP}"
    TIER_ELAPSED["T4"]="${TIER_ELAPSED["T0"]:-0}"
fi

# --- Tier 1: Rust workspace (Docker) -----------------------------------------

if $RUN_TIER1; then
    if ! $DOCKER_OK; then
        skip_tier "Tier 1 - Rust workspace" "T1" "Docker not available"
    else
        run_tier "Tier 1 - Rust workspace (Docker)" "T1" \
            bash "$SCRIPT_DIR/tier1/run.sh" $NO_CACHE
    fi
fi

# --- Tier 2: .NET cross-compile (Docker) -------------------------------------

if $RUN_TIER2; then
    if ! $DOCKER_OK; then
        skip_tier "Tier 2 - .NET cross-compile" "T2" "Docker not available"
    else
        run_tier "Tier 2 - .NET cross-compile (Docker)" "T2" \
            bash "$SCRIPT_DIR/tier2/run.sh" $NO_CACHE
    fi
fi

# --- Print summary and exit ---------------------------------------------------

print_summary

if $OVERALL_PASS; then
    exit 0
else
    exit 1
fi

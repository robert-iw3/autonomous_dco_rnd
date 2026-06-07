#!/usr/bin/env bash
# ==============================================================================
# 03_download_python_deps.sh
# Download all Python wheels for offline pip install.
# Sources: deployment_prep/python_requirements.txt (aggregated top-level deps)
# + mlops/requirements.txt (full pinned hash list)
#
# Run on: internet-connected machine (ONLINE phase)
# Output: deployment_prep/wheels/
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PREP_DIR}/.." && pwd)"

WHEELS_DIR="${PREP_DIR}/wheels"
mkdir -p "${WHEELS_DIR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "${CYAN}[pip]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[+]${NC} $*"; }
log_error(){ echo -e "${RED}[!]${NC} $*" >&2; }

# Determine Python binary
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
    log_error "python3 not found. Set PYTHON env var if using a venv."
    exit 1
fi

download_reqs() {
    local label="$1"
    local req_file="$2"
    if [[ ! -f "$req_file" ]]; then
        log_info "  Not found, skipping: ${req_file}"
        return 0
    fi
    log_info "  Downloading wheels for: ${label}"
    "$PYTHON" -m pip download \
        --dest "${WHEELS_DIR}" \
        --no-cache-dir \
        -r "${req_file}" \
        2>&1 | tail -3 || {
        log_error "  pip download failed for ${label} -- continuing"
    }
}

log_info "=== Phase 3: Download Python Wheels ==="

download_reqs "deployment_prep aggregated"    "${PREP_DIR}/python_requirements.txt"
download_reqs "mlops (full pinned)"           "${REPO_ROOT}/mlops/requirements.txt"
download_reqs "llm_hunter agents"             "${REPO_ROOT}/analytics/llm_hunter/requirements.txt"
download_reqs "nexus_hunter agent tools"      "${REPO_ROOT}/infrastructure/ansible/roles/nexus_hunter/files/requirements.txt"
download_reqs "scan tooling"                  "${PREP_DIR}/scan/requirements.txt"

TOTAL=$(ls "${WHEELS_DIR}"/*.whl 2>/dev/null | wc -l)
TOTAL_TAR=$(ls "${WHEELS_DIR}"/*.tar.gz 2>/dev/null | wc -l)
log_ok "Downloaded ${TOTAL} wheel(s) + ${TOTAL_TAR} sdist(s) into ${WHEELS_DIR}/"
log_ok "Offline install: pip install --no-index --find-links ${WHEELS_DIR}/ -r <requirements.txt>"

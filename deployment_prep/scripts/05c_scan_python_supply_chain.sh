#!/usr/bin/env bash
# ==============================================================================
# 05c_scan_python_supply_chain.sh
# Run GuardDog supply-chain scanning on all Python requirements files.
#
# The CANONICAL scan target is deployment_prep/python_requirements.txt —
# the single source of truth for all Python dependencies in the project.
# This file MUST be updated whenever any new dependency is introduced in
# mlops/, analytics/, services/, or infrastructure/ (see its header for
# the component requirements it aggregates).
#
# Additional requirements*.txt files found in the repo are scanned as
# supplemental coverage to catch anything not yet promoted to the central list.
#
# GuardDog detects malicious packages via heuristics including:
#   typosquatting, dependency confusion, code-execution hooks, data
#   exfiltration, obfuscated APIs, and bundled binaries.
#
# False-positive rules for ML frameworks are whitelisted in
# deployment_prep/supply_chain/guarddog-config.yaml.
#
# Run on: internet-connected machine (ONLINE phase, after deps)
# Output: deployment_prep/supply_chain/reports/guarddog_<reqfile>_<ts>.txt
#         deployment_prep/supply_chain/reports/guarddog_summary_<ts>.txt
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PREP_DIR}/.." && pwd)"
SC_DIR="${PREP_DIR}/supply_chain"
REPORTS_DIR="${SC_DIR}/reports"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

source "${SCRIPT_DIR}/lib_container.sh"

mkdir -p "${REPORTS_DIR}"

GUARDDOG_IMAGE="local/nexus-guarddog-scanner:latest"
CONFIG_FILE="${SC_DIR}/guarddog-config.yaml"
SUMMARY_FILE="${REPORTS_DIR}/guarddog_summary_${TIMESTAMP}.txt"

# Set to 'true' to block packaging on any unwhitelisted finding
GUARDDOG_DENY="${GUARDDOG_DENY:-false}"

log_info "=== Phase 5c: Python Supply-Chain Scan (GuardDog) ==="
log_info "  Canonical list: deployment_prep/python_requirements.txt"
log_info "  Runtime:        ${CONTAINER_RT}"
log_info "  Deny findings:  ${GUARDDOG_DENY}"
log_info "  Config:         ${CONFIG_FILE#${REPO_ROOT}/}"
log_info "  Reports dir:    ${REPORTS_DIR#${REPO_ROOT}/}"

# ── Build GuardDog scanner image ──────────────────────────────────────────────
log_info "  Building GuardDog scanner image (${GUARDDOG_IMAGE})..."
${CONTAINER_RT} build \
    --quiet \
    -t "${GUARDDOG_IMAGE}" \
    -f "${SC_DIR}/Dockerfile" \
    "${SC_DIR}" || {
    log_error "Failed to build GuardDog image from ${SC_DIR}/Dockerfile"
    exit 1
}
log_ok "  GuardDog image ready"

# ── Determine files to scan ───────────────────────────────────────────────────
# The canonical list is always first; remaining requirements files are supplemental.
CANONICAL="${PREP_DIR}/python_requirements.txt"

if [[ ! -f "${CANONICAL}" ]]; then
    log_error "Canonical requirements file not found: ${CANONICAL}"
    log_error "Create deployment_prep/python_requirements.txt before running this phase."
    exit 1
fi

# Collect supplemental requirements files (exclude canonical + generated/test noise)
mapfile -t SUPPLEMENTAL < <(find "${REPO_ROOT}" \
    -name "requirements*.txt" \
    -not -path "*/target/*" \
    -not -path "*/.git/*" \
    -not -path "*/node_modules/*" \
    -not -path "*/\.*" \
    -not -path "${CANONICAL}" \
    | sort)

# Scan canonical first, then supplemental
ALL_REQ_FILES=("${CANONICAL}" "${SUPPLEMENTAL[@]}")

log_info "  Scanning ${#ALL_REQ_FILES[@]} file(s) (1 canonical + ${#SUPPLEMENTAL[@]} supplemental)"

{
    echo "GuardDog Supply-Chain Summary — ${TIMESTAMP}"
    echo "Runtime: ${CONTAINER_RT}"
    echo "Deny on findings: ${GUARDDOG_DENY}"
    echo "Canonical list: ${CANONICAL#${REPO_ROOT}/}"
    echo "---"
} > "${SUMMARY_FILE}"

BLOCKED=false
TOTAL_SCANNED=0
TOTAL_FLAGGED=0

# ── Helper: scan one requirements file ───────────────────────────────────────
scan_req_file() {
    local req_file="$1"
    local label="$2"   # "CANONICAL" or "supplemental"
    local rel_path="${req_file#${REPO_ROOT}/}"
    local safe_name="${rel_path//\//_}"
    local report_file="${REPORTS_DIR}/guarddog_${safe_name}_${TIMESTAMP}.txt"

    log_info "  [${label}] ${rel_path}"

    # Parse package names (strip version pins, extras, comments, URL/flag lines)
    mapfile -t PKGS < <(grep -vE '^\s*(#|$|-r |-c |-e |--|-f |http)' "${req_file}" \
        | sed 's/[=><!;@ ].*$//' \
        | sed 's/\[.*\]$//' \
        | grep -vE '^\s*$' \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u)

    if [[ ${#PKGS[@]} -eq 0 ]]; then
        log_warn "    No parseable packages — skipping"
        echo "${rel_path} [${label}]: no packages (skipped)" >> "${SUMMARY_FILE}"
        return
    fi

    log_info "    ${#PKGS[@]} package(s)"

    {
        echo "GuardDog scan: ${rel_path} [${label}]"
        echo "Timestamp: ${TIMESTAMP}"
        echo "Packages: ${#PKGS[@]}"
        echo "---"
    } > "${report_file}"

    local FINDINGS=0

    for pkg in "${PKGS[@]}"; do
        SCAN_EXIT=0
        PKG_OUTPUT=$(${CONTAINER_RT} run --rm \
            --network none \
            -v "${CONFIG_FILE}:/workspace/guarddog-config.yaml:ro" \
            "${GUARDDOG_IMAGE}" \
            /venv/bin/guarddog pypi scan "${pkg}" \
            --config /workspace/guarddog-config.yaml \
            2>&1) || SCAN_EXIT=$?

        {
            echo ""
            echo "### ${pkg}"
            echo "${PKG_OUTPUT}"
        } >> "${report_file}"

        if [[ "${SCAN_EXIT}" -ne 0 ]] || \
           echo "${PKG_OUTPUT}" | grep -qiE "(malicious|suspicious|WARNING|FAIL|❌)"; then
            FINDINGS=$(( FINDINGS + 1 ))
            log_warn "    FLAGGED: ${pkg}"
        fi

        TOTAL_SCANNED=$(( TOTAL_SCANNED + 1 ))
        sleep 1  # rate-limit PyPI API calls
    done

    echo "${rel_path} [${label}]: ${#PKGS[@]} packages, ${FINDINGS} flagged" \
        >> "${SUMMARY_FILE}"

    if [[ "${FINDINGS}" -gt 0 ]]; then
        log_warn "  ${rel_path}: ${FINDINGS} package(s) flagged — ${report_file#${REPO_ROOT}/}"
        TOTAL_FLAGGED=$(( TOTAL_FLAGGED + FINDINGS ))
        [[ "${GUARDDOG_DENY}" == "true" ]] && BLOCKED=true
    else
        log_ok "  ${rel_path}: clean"
    fi
}

# ── Scan canonical list first (mandatory) ────────────────────────────────────
scan_req_file "${CANONICAL}" "CANONICAL"

# ── Scan supplemental files ───────────────────────────────────────────────────
for req_file in "${SUPPLEMENTAL[@]}"; do
    scan_req_file "${req_file}" "supplemental"
done

{
    echo "---"
    echo "Total packages scanned: ${TOTAL_SCANNED}"
    echo "Total flagged:          ${TOTAL_FLAGGED}"
    echo "Blocked:                ${BLOCKED}"
} >> "${SUMMARY_FILE}"

log_info ""
log_ok "Summary → ${SUMMARY_FILE#${REPO_ROOT}/}"
log_ok "Scanned ${TOTAL_SCANNED} packages — ${TOTAL_FLAGGED} flagged"

if [[ "${BLOCKED}" == "true" ]]; then
    log_error "BLOCKED: supply-chain findings above threshold."
    log_error "  Review reports in ${REPORTS_DIR}/"
    log_error "  Set GUARDDOG_DENY=false to downgrade to warnings."
    exit 1
fi

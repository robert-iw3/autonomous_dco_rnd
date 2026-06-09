#!/usr/bin/env bash
# ==============================================================================
# 05b_cargo_audit.sh
# Run `cargo audit` on every Rust workspace in the repo and regenerate any
# stale or missing Cargo.lock files before the image-scan and packaging phases.
#
# Exits non-zero if any workspace has vulnerabilities above the configured
# threshold (CARGO_AUDIT_DENY=critical|high|all; default: critical).
#
# Run on: internet-connected machine (ONLINE phase, after deps)
# Output: deployment_prep/supply_chain/reports/cargo_audit_<workspace>_<ts>.json
#         deployment_prep/supply_chain/reports/cargo_audit_summary_<ts>.txt
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PREP_DIR}/.." && pwd)"
REPORTS_DIR="${PREP_DIR}/supply_chain/reports"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "${CYAN}[cargo-audit]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[+]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error(){ echo -e "${RED}[!]${NC} $*" >&2; }

mkdir -p "${REPORTS_DIR}"

# Vulnerability deny threshold: critical (default) | high | all | none
CARGO_AUDIT_DENY="${CARGO_AUDIT_DENY:-critical}"
BLOCKED=false
SUMMARY_FILE="${REPORTS_DIR}/cargo_audit_summary_${TIMESTAMP}.txt"

log_info "=== Phase 5b: Cargo Audit + Lockfile Generation ==="
log_info "  Deny threshold: ${CARGO_AUDIT_DENY}"
log_info "  Reports dir:    ${REPORTS_DIR}"

# ── Ensure cargo-audit is available ──────────────────────────────────────────
if ! command -v cargo-audit &>/dev/null; then
    if command -v cargo &>/dev/null; then
        log_info "  cargo-audit not installed — installing via cargo..."
        cargo install cargo-audit --quiet
        log_ok "  cargo-audit installed"
    else
        log_error "cargo not found. Install the Rust toolchain (https://rustup.rs) before running this phase."
        exit 1
    fi
fi

# ── Discover all Rust workspace roots ────────────────────────────────────────
# A workspace root is a directory containing Cargo.toml that is NOT itself
# inside another workspace root already on the list (avoids auditing member
# crates individually, which duplicates findings).
mapfile -t ALL_TOMLS < <(find "${REPO_ROOT}" \
    -name "Cargo.toml" \
    -not -path "*/target/*" \
    -not -path "*/.git/*" \
    | sort)

WORKSPACE_ROOTS=()
for toml in "${ALL_TOMLS[@]}"; do
    toml_dir="$(dirname "$toml")"
    is_member=false
    for existing in "${WORKSPACE_ROOTS[@]+"${WORKSPACE_ROOTS[@]}"}"; do
        if [[ "$toml_dir" == "${existing}"/* ]]; then
            is_member=true
            break
        fi
    done
    [[ "$is_member" == "false" ]] && WORKSPACE_ROOTS+=("$toml_dir")
done

if [[ ${#WORKSPACE_ROOTS[@]} -eq 0 ]]; then
    log_warn "No Cargo.toml found under ${REPO_ROOT} — skipping cargo audit."
    echo "NO_RUST_WORKSPACES" > "${SUMMARY_FILE}"
    exit 0
fi

log_info "  Found ${#WORKSPACE_ROOTS[@]} Rust workspace root(s)"

{
    echo "Cargo Audit Summary — ${TIMESTAMP}"
    echo "Deny threshold: ${CARGO_AUDIT_DENY}"
    echo "Repo: ${REPO_ROOT}"
    echo "---"
} > "${SUMMARY_FILE}"

TOTAL_VULNS=0
TOTAL_CRITICAL=0

# ── Parse vulnerability counts from cargo-audit JSON output ──────────────────
_count_vulns() {
    local json_file="$1"
    python3 - "${json_file}" <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    vulns = data.get("vulnerabilities", {}).get("list", [])
    crits = 0
    for v in vulns:
        cvss = v.get("advisory", {}).get("cvss")
        try:
            score = float(str(cvss).split("/")[0]) if cvss else 0.0
            if score >= 9.0:
                crits += 1
        except (ValueError, TypeError):
            pass
    print(f"{len(vulns)} {crits}")
except Exception as e:
    print("0 0")
PYEOF
}

# ── Audit each workspace ──────────────────────────────────────────────────────
for ws_dir in "${WORKSPACE_ROOTS[@]}"; do
    ws_name="$(basename "${ws_dir}")"
    lock_file="${ws_dir}/Cargo.lock"
    report_file="${REPORTS_DIR}/cargo_audit_${ws_name}_${TIMESTAMP}.json"

    log_info "  Workspace: ${ws_dir#${REPO_ROOT}/}"

    # Generate Cargo.lock if absent (library crates may not have one)
    if [[ ! -f "${lock_file}" ]]; then
        log_info "    Cargo.lock absent — running cargo generate-lockfile..."
        if ! (cd "${ws_dir}" && cargo generate-lockfile --quiet 2>&1); then
            log_warn "    Could not generate lockfile for '${ws_name}' — skipping (may be a library-only crate)"
            echo "  ${ws_name}: SKIPPED (no lockfile)" >> "${SUMMARY_FILE}"
            continue
        fi
        log_ok "    Cargo.lock generated"
    else
        log_info "    Cargo.lock present — refreshing with cargo update..."
        (cd "${ws_dir}" && cargo update --quiet 2>&1 || true)
    fi

    # Run cargo audit and capture JSON output
    log_info "    Running cargo audit..."
    AUDIT_EXIT=0
    cargo audit \
        --json \
        --file "${lock_file}" \
        > "${report_file}" 2>/dev/null || AUDIT_EXIT=$?

    # Parse counts from JSON
    read -r VULN_COUNT CRITICAL_COUNT < <(_count_vulns "${report_file}" 2>/dev/null || echo "0 0")

    STATUS="PASS"
    [[ "${AUDIT_EXIT}" -ne 0 ]] && STATUS="FAIL"

    echo "  ${ws_name}: ${VULN_COUNT} vulnerabilities, ${CRITICAL_COUNT} critical — ${STATUS}" \
        >> "${SUMMARY_FILE}"

    if [[ "${AUDIT_EXIT}" -ne 0 ]]; then
        log_warn "    ${ws_name}: ${VULN_COUNT} vulnerability/ies (${CRITICAL_COUNT} critical)"
        TOTAL_VULNS=$(( TOTAL_VULNS + VULN_COUNT ))
        TOTAL_CRITICAL=$(( TOTAL_CRITICAL + CRITICAL_COUNT ))
        case "${CARGO_AUDIT_DENY}" in
            critical) [[ "${CRITICAL_COUNT}" -gt 0 ]] && BLOCKED=true ;;
            high|all)  BLOCKED=true ;;
            none)      : ;;
        esac
    else
        log_ok "    ${ws_name}: clean"
    fi

    log_info "    Report → ${report_file#${REPO_ROOT}/}"
done

{
    echo "---"
    echo "Total vulnerabilities: ${TOTAL_VULNS}"
    echo "Total critical:        ${TOTAL_CRITICAL}"
    echo "Blocked:               ${BLOCKED}"
} >> "${SUMMARY_FILE}"

log_info ""
log_ok "Audit summary → ${SUMMARY_FILE#${REPO_ROOT}/}"

if [[ "${BLOCKED}" == "true" ]]; then
    log_error "BLOCKED: critical vulnerabilities detected. Review reports in ${REPORTS_DIR}/"
    log_error "  Adjust CARGO_AUDIT_DENY=high|all to change the threshold, or 'none' to warn only."
    exit 1
fi

log_ok "Cargo audit complete — ${TOTAL_VULNS} total, ${TOTAL_CRITICAL} critical (threshold: ${CARGO_AUDIT_DENY})"

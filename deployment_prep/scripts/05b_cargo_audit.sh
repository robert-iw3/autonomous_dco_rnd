#!/usr/bin/env bash
# ==============================================================================
# 05b_cargo_audit.sh
# Run `cargo audit` on every Rust workspace in the repo and regenerate any
# stale or missing Cargo.lock files before the image-scan and packaging phases.
#
# Exits non-zero if any workspace has vulnerabilities above the configured
# threshold (CARGO_AUDIT_DENY=critical|high|all; default: critical). Under
# 'critical', advisories with no usable CVSS vector and reports that cannot be
# parsed also block — an undetermined severity is not evidence of a safe one.
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
TOTAL_UNRATED=0
TOTAL_UNREADABLE=0

# ── Parse vulnerability counts from cargo-audit JSON output ──────────────────
# advisory.cvss is a CVSS v3 *vector string* ("CVSS:3.1/AV:N/..."), not a number,
# so the base score has to be computed from the vector. Advisories whose severity
# cannot be determined are counted as unrated, never as non-critical.
# Prints "<total> <critical> <unrated>"; exits non-zero if the report is unreadable.
_count_vulns() {
    local json_file="$1"
    python3 - "${json_file}" <<'PYEOF'
import json, sys

AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC  = {"L": 0.77, "H": 0.44}
PR  = {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
       "C": {"N": 0.85, "L": 0.68, "H": 0.50}}
UI  = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(x):
    """CVSS v3.1 Appendix A Roundup — round up to one decimal place."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def base_score(vector):
    """CVSS v3.x base score for a vector string, or None if it is unusable."""
    parts = str(vector).split("/")
    if not parts[0].startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in parts[1:] if ":" in p)
    try:
        scope = m["S"]
        iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
        impact = 6.42 * iss if scope == "U" else \
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * AV[m["AV"]] * AC[m["AC"]] * PR[scope][m["PR"]] * UI[m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if scope == "U":
        return roundup(min(impact + expl, 10.0))
    return roundup(min(1.08 * (impact + expl), 10.0))


data = json.load(open(sys.argv[1]))
vulns = data.get("vulnerabilities", {}).get("list", [])
crits = 0
unrated = 0
for v in vulns:
    cvss = v.get("advisory", {}).get("cvss")
    score = base_score(cvss) if cvss else None
    if score is None:
        unrated += 1
    elif score >= 9.0:
        crits += 1
print(f"{len(vulns)} {crits} {unrated}")
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

    # Parse counts from JSON. A report we cannot read is not a clean report —
    # cargo audit that never produced usable output must block, not pass.
    if ! COUNTS="$(_count_vulns "${report_file}" 2>&1)"; then
        log_error "    ${ws_name}: cargo-audit report unreadable — audit did not complete"
        echo "  ${ws_name}: UNREADABLE report — AUDIT ERROR (exit ${AUDIT_EXIT})" >> "${SUMMARY_FILE}"
        TOTAL_UNREADABLE=$(( TOTAL_UNREADABLE + 1 ))
        [[ "${CARGO_AUDIT_DENY}" != "none" ]] && BLOCKED=true
        log_info "    Report → ${report_file#${REPO_ROOT}/}"
        continue
    fi
    read -r VULN_COUNT CRITICAL_COUNT UNRATED_COUNT <<< "${COUNTS}"
    : "${VULN_COUNT:=0}" "${CRITICAL_COUNT:=0}" "${UNRATED_COUNT:=0}"

    STATUS="PASS"
    [[ "${AUDIT_EXIT}" -ne 0 ]] && STATUS="FAIL"

    echo "  ${ws_name}: ${VULN_COUNT} vulnerabilities, ${CRITICAL_COUNT} critical, ${UNRATED_COUNT} unrated — ${STATUS}" \
        >> "${SUMMARY_FILE}"

    if [[ "${AUDIT_EXIT}" -ne 0 ]]; then
        log_warn "    ${ws_name}: ${VULN_COUNT} vulnerability/ies (${CRITICAL_COUNT} critical, ${UNRATED_COUNT} unrated)"
        TOTAL_VULNS=$(( TOTAL_VULNS + VULN_COUNT ))
        TOTAL_CRITICAL=$(( TOTAL_CRITICAL + CRITICAL_COUNT ))
        TOTAL_UNRATED=$(( TOTAL_UNRATED + UNRATED_COUNT ))
        case "${CARGO_AUDIT_DENY}" in
            critical) [[ "${CRITICAL_COUNT}" -gt 0 || "${UNRATED_COUNT}" -gt 0 ]] && BLOCKED=true ;;
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
    echo "Total unrated:         ${TOTAL_UNRATED}"
    echo "Unreadable reports:    ${TOTAL_UNREADABLE}"
    echo "Blocked:               ${BLOCKED}"
} >> "${SUMMARY_FILE}"

log_info ""
log_ok "Audit summary → ${SUMMARY_FILE#${REPO_ROOT}/}"

if [[ "${BLOCKED}" == "true" ]]; then
    log_error "BLOCKED: ${TOTAL_CRITICAL} critical, ${TOTAL_UNRATED} unrated, ${TOTAL_UNREADABLE} unreadable report(s). Review reports in ${REPORTS_DIR}/"
    log_error "  Adjust CARGO_AUDIT_DENY=high|all to change the threshold, or 'none' to warn only."
    exit 1
fi

log_ok "Cargo audit complete — ${TOTAL_VULNS} total, ${TOTAL_CRITICAL} critical, ${TOTAL_UNRATED} unrated (threshold: ${CARGO_AUDIT_DENY})"

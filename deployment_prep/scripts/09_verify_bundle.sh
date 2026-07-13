#!/usr/bin/env bash
# ==============================================================================
# 09_verify_bundle.sh
# Verify SHA-256 integrity of all bundle artifacts before offline deployment.
# Run this on the air-gapped TARGET immediately after unpacking the bundle.
#
# Run on: air-gapped target (OFFLINE phase, before deploy.sh --offline)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log_info()  { echo -e "${CYAN}[verify]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[!] ERROR:${NC} $*" >&2; }

SHA_FILE="${PREP_DIR}/manifests/sha256sums.txt"
MANIFEST_FILE="${PREP_DIR}/manifests/deployment_manifest.json"

log_info "=== Bundle Integrity Verification ==="
log_info "  SHA256 index:  ${SHA_FILE}"
log_info "  Manifest:      ${MANIFEST_FILE}"
log_info ""

if [[ ! -f "${SHA_FILE}" ]]; then
    log_error "SHA-256 index not found at ${SHA_FILE}"
    log_error "Bundle may be incomplete or corrupted."
    exit 1
fi

PASS=0; FAIL=0; MISSING=0

while IFS= read -r line; do
    expected_hash="${line%%  *}"
    rel_path="${line#*  }"
    abs_path="${PREP_DIR}/../${rel_path}"

    if [[ ! -f "${abs_path}" ]]; then
        log_warn "  MISSING: ${rel_path}"
        (( MISSING++ )) || true
        continue
    fi

    actual_hash="$(sha256sum "${abs_path}" | cut -d' ' -f1)"
    if [[ "$actual_hash" == "$expected_hash" ]]; then
        (( PASS++ )) || true
    else
        log_error "  HASH MISMATCH: ${rel_path}"
        log_error "    expected: ${expected_hash}"
        log_error "    actual:   ${actual_hash}"
        (( FAIL++ )) || true
    fi
done < "${SHA_FILE}"

echo ""
log_info "Results: ${PASS} OK  /  ${FAIL} MISMATCH  /  ${MISSING} MISSING"

if [[ "$FAIL" -gt 0 || "$MISSING" -gt 0 ]]; then
    log_error "${BOLD}Bundle verification FAILED. Do not proceed with deployment.${NC}"
    log_error "Re-download the bundle from the preparation machine."
    exit 1
fi

log_ok "${BOLD}All ${PASS} file(s) verified -- bundle integrity confirmed.${NC}"
log_info ""
log_info "Next step: load images into the local container runtime"
log_info "  docker:  bash scripts/10_load_images.sh"
log_info "  podman:  NEXUS_CONTAINER_RUNTIME=podman bash scripts/10_load_images.sh"

#!/usr/bin/env bash
# ==============================================================================
# 08_package_bundle.sh
# Package all bundle artifacts + manifests + prep scripts into a single
# dated tar.gz for physical transport to the air-gapped target environment.
#
# The bundle is self-contained: unpack it, verify with 09_verify_bundle.sh,
# then run deploy.sh --offline from the same machine.
#
# Run on: internet-connected machine (ONLINE phase, final step)
# Output: deployment_prep/nexus_bundle_<YYYYMMDD_HHMMSS>.tar.gz
#         deployment_prep/nexus_bundle_<YYYYMMDD_HHMMSS>.tar.gz.sha256
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PREP_DIR}/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "${CYAN}[bundle]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[+]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error(){ echo -e "${RED}[!]${NC} $*" >&2; }

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BUNDLE_NAME="nexus_bundle_${TIMESTAMP}"
BUNDLE_TAR="${PREP_DIR}/${BUNDLE_NAME}.tar.gz"
BUNDLE_SHA="${BUNDLE_TAR}.sha256"

# Validate required artifacts exist before packaging
check_required() {
    local dir="$1"; local label="$2"
    local count
    count=$(find "${PREP_DIR}/${dir}" -maxdepth 1 -name "*.tar.gz" 2>/dev/null | wc -l)
    if [[ "$count" -eq 0 ]]; then
        log_warn "  ${label}: no .tar.gz files found in ${dir}/ -- run earlier phases first"
        return 1
    fi
    log_info "  ${label}: ${count} archive(s)"
    return 0
}

log_info "=== Phase 8: Package Air-Gap Bundle ==="

MISSING=false
check_required "images"        "Runtime images"       || MISSING=true
check_required "custom-images" "Custom images"        || MISSING=true

if [[ ! -f "${PREP_DIR}/manifests/sha256sums.txt" ]]; then
    log_warn "  SHA-256 manifest not found -- run script 07 first"
    MISSING=true
fi
if [[ ! -f "${PREP_DIR}/manifests/deployment_manifest.json" ]]; then
    log_warn "  Deployment manifest not found -- run script 07 first"
    MISSING=true
fi

if [[ "$MISSING" == "true" ]]; then
    log_error "Required artifacts missing. Complete phases 01-07 before packaging."
    exit 1
fi

log_info "Packaging bundle: ${BUNDLE_NAME}.tar.gz"
log_info "  This may take several minutes for large image archives..."

# What to include in the bundle
INCLUDE_DIRS=(
    "deployment_prep/images"
    "deployment_prep/custom-images"
    "deployment_prep/wheels"
    "deployment_prep/collections"
    "deployment_prep/providers"
    "deployment_prep/scan/reports"
    "deployment_prep/scan/Dockerfile"
    "deployment_prep/scan/scan_config.json"
    "deployment_prep/supply_chain"
    "deployment_prep/manifests"
    "deployment_prep/scripts"
    "deployment_prep/image_manifest.json"
    "deployment_prep/python_requirements.txt"
    "deployment_prep/ansible_requirements.yml"
    # Top-level deployment scripts for offline use
    "deploy.sh"
    "orchestration/scripts"
    "orchestration/environments"
    "orchestration/templates"
    "infrastructure/ansible"
    "infrastructure/prometheus"
    "infrastructure/qdrant"
    "infrastructure/haproxy"
    "infrastructure/nats"
)

cd "${REPO_ROOT}"
tar_args=()
for item in "${INCLUDE_DIRS[@]}"; do
    [[ -e "$item" ]] && tar_args+=("$item")
done

tar -czf "${BUNDLE_TAR}" "${tar_args[@]}" \
    --exclude="*.pyc" \
    --exclude="__pycache__" \
    --exclude=".git" \
    --exclude=".terraform" \
    --exclude="*.log"

log_info "Computing bundle SHA-256..."
sha256sum "${BUNDLE_TAR}" > "${BUNDLE_SHA}"
BUNDLE_SIZE=$(du -sh "${BUNDLE_TAR}" | cut -f1)
BUNDLE_HASH=$(cut -d' ' -f1 "${BUNDLE_SHA}")

log_ok "Bundle: ${BUNDLE_NAME}.tar.gz (${BUNDLE_SIZE})"
log_ok "SHA256: ${BUNDLE_HASH}"
log_ok "Hash file: ${BUNDLE_SHA}"
log_info ""
log_info "Transport to air-gapped target, then:"
log_info "  1. Copy ${BUNDLE_NAME}.tar.gz + ${BUNDLE_NAME}.tar.gz.sha256 to target"
log_info "  2. sha256sum -c ${BUNDLE_NAME}.tar.gz.sha256"
log_info "  3. tar -xzf ${BUNDLE_NAME}.tar.gz"
log_info "  4. cd <extracted>/deployment_prep && bash scripts/09_verify_bundle.sh"
log_info "  5. Review supply_chain/reports/ for cargo audit + GuardDog scan findings"
log_info "  6. cd <extracted> && bash deploy.sh --offline"

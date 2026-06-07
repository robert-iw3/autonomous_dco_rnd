#!/usr/bin/env bash
# ==============================================================================
# 05_download_terraform_deps.sh
# Mirror Terraform providers for offline deployment.
# Creates a local filesystem mirror that Terraform can use without internet.
#
# Run on: internet-connected machine (ONLINE phase)
# Output: deployment_prep/providers/ (filesystem provider mirror)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PREP_DIR}/.." && pwd)"

PROVIDERS_DIR="${PREP_DIR}/providers"
mkdir -p "${PROVIDERS_DIR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "${CYAN}[terraform]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[+]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error(){ echo -e "${RED}[!]${NC} $*" >&2; }

if ! command -v terraform &>/dev/null; then
    log_warn "terraform not found -- skipping provider mirror."
    log_warn "Install terraform and re-run if deploying to AWS or VMware."
    exit 0
fi

TF_DIRS=(
    "${REPO_ROOT}/infrastructure/terraform/aws"
    "${REPO_ROOT}/infrastructure/terraform/vmware"
    "${REPO_ROOT}/infrastructure/terraform"
)

log_info "=== Phase 5: Mirror Terraform Providers ==="
for tf_dir in "${TF_DIRS[@]}"; do
    [[ -d "$tf_dir" ]] || continue
    log_info "  Mirroring providers from: ${tf_dir}"
    pushd "$tf_dir" > /dev/null
    terraform providers mirror "${PROVIDERS_DIR}" 2>&1 | tail -5 || \
        log_warn "  Mirror from ${tf_dir} had warnings -- continuing"
    popd > /dev/null
done

log_ok "Provider mirror complete → ${PROVIDERS_DIR}/"
log_ok "Offline usage: add to ~/.terraformrc:"
log_ok "  provider_installation {"
log_ok "    filesystem_mirror { path = \"${PROVIDERS_DIR}\" }"
log_ok "    direct { exclude = [\"*\"] }"
log_ok "  }"

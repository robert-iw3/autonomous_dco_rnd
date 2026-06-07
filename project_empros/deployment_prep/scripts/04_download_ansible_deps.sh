#!/usr/bin/env bash
# ==============================================================================
# 04_download_ansible_deps.sh
# Download Ansible Galaxy collections and Terraform providers for offline use.
#
# Run on: internet-connected machine     (ONLINE phase)
# Output: deployment_prep/collections/   (Ansible collections)
#         deployment_prep/providers/     (Terraform provider mirror)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PREP_DIR}/.." && pwd)"

COLLECTIONS_DIR="${PREP_DIR}/collections"
mkdir -p "${COLLECTIONS_DIR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "${CYAN}[ansible]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[+]${NC} $*"; }
log_error(){ echo -e "${RED}[!]${NC} $*" >&2; }

log_info "=== Phase 4a: Download Ansible Collections ==="

REQS="${PREP_DIR}/ansible_requirements.yml"
if [[ ! -f "$REQS" ]]; then
    log_error "ansible_requirements.yml not found at ${REQS}"
    exit 1
fi

if ! command -v ansible-galaxy &>/dev/null; then
    log_error "ansible-galaxy not found. Install ansible-core first."
    exit 1
fi

log_info "  Downloading collections to ${COLLECTIONS_DIR}..."
ansible-galaxy collection download \
    -r "${REQS}" \
    -p "${COLLECTIONS_DIR}" \
    --no-deps 2>&1 | tail -5 || log_error "  Some collections failed -- check output above"

# Re-run with deps to get transitive dependencies
ansible-galaxy collection download \
    -r "${REQS}" \
    -p "${COLLECTIONS_DIR}" \
    2>&1 | tail -5 || true

TOTAL=$(ls "${COLLECTIONS_DIR}"/*.tar.gz 2>/dev/null | wc -l)
log_ok "  Downloaded ${TOTAL} collection(s) into ${COLLECTIONS_DIR}/"
log_ok "  Offline install: ansible-galaxy collection install --offline -p /path/collections/ -r ansible_requirements.yml"

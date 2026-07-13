#!/usr/bin/env bash
# ==============================================================================
# 01_pull_and_save_images.sh
# Pull all runtime + build-base images from image_manifest.json and save them
# as compressed tarballs into deployment_prep/images/.
#
# Run on: internet-connected machine (ONLINE phase)
# Output: deployment_prep/images/<name>.tar.gz
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${SCRIPT_DIR}/lib_container.sh"

MANIFEST="${PREP_DIR}/image_manifest.json"
IMAGES_DIR="${PREP_DIR}/images"
mkdir -p "${IMAGES_DIR}"

# Parse manifest with python3 (no jq dependency required)
parse_images() {
    python3 - "$MANIFEST" "$1" <<'EOF'
import json, sys
data = json.load(open(sys.argv[1]))
section = sys.argv[2]
for img in data.get(section, []):
    print(f"{img['repo']}|{img['save_as']}")
EOF
}

pull_and_save() {
    local repo="$1"
    local save_as="$2"
    local dest="${IMAGES_DIR}/${save_as}"

    if [[ -f "$dest" ]]; then
        log_warn "  Already exists, skipping: ${save_as}"
        return 0
    fi

    log_info "  Pulling: ${repo}"
    if ! $CT_PULL "${repo}"; then
        log_error "  FAILED to pull: ${repo}"
        return 1
    fi

    log_info "  Saving:  ${repo} → ${save_as}"
    local tmp="${dest%.gz}"
    $CT_SAVE "${repo}" -o "${tmp}"
    gzip -9 "${tmp}"
    log_ok "  Saved:   ${save_as} ($(du -sh "${dest}" | cut -f1))"
}

log_info "=== Phase 1: Pull + Save Runtime Images ==="
FAILED=()
while IFS='|' read -r repo save_as; do
    [[ -z "$repo" ]] && continue
    pull_and_save "$repo" "$save_as" || FAILED+=("$repo")
done < <(parse_images "runtime_images")

log_info ""
log_info "=== Phase 1b: Pull + Save Build-Base Images ==="
while IFS='|' read -r repo save_as; do
    [[ -z "$repo" ]] && continue
    pull_and_save "$repo" "$save_as" || FAILED+=("$repo")
done < <(parse_images "build_base_images")

log_info ""
log_info "=== Summary ==="
TOTAL=$(ls "${IMAGES_DIR}"/*.tar.gz 2>/dev/null | wc -l)
log_ok "  ${TOTAL} image archive(s) in ${IMAGES_DIR}/"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    log_error "  ${#FAILED[@]} pull(s) failed: ${FAILED[*]}"
    exit 1
fi
log_ok "All images pulled and saved successfully."

#!/usr/bin/env bash
# ==============================================================================
# 10_load_images.sh
# Load all image tarballs into the local container runtime on the air-gapped
# target. Must be run on every host that will run containers before
# docker/podman compose up.
#
# Run on: air-gapped TARGET hosts (OFFLINE phase, after 09_verify_bundle.sh)
# Supports: docker or podman (auto-detected via lib_container.sh)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "${SCRIPT_DIR}/lib_container.sh"

IMAGES_DIR="${PREP_DIR}/images"
CUSTOM_DIR="${PREP_DIR}/custom-images"

load_dir() {
    local dir="$1"
    local label="$2"
    [[ -d "$dir" ]] || { log_warn "  ${label} dir not found: ${dir}"; return 0; }

    local count=0
    while IFS= read -r archive; do
        [[ -z "$archive" ]] && continue
        local name; name="$(basename "${archive}")"
        log_info "  Loading: ${name}"
        # pipe through gzip -d for portability
        if gzip -dc "${archive}" | $CT_LOAD; then
            log_ok "    Loaded: ${name}"
            (( count++ )) || true
        else
            log_error "  FAILED to load: ${name}"
        fi
    done < <(find "$dir" -maxdepth 1 -name "*.tar.gz" | sort)

    log_ok "  ${count} image(s) loaded from ${label}"
}

log_info "=== Phase 10: Load Images (${CONTAINER_RT}) ==="
load_dir "${IMAGES_DIR}" "runtime images"
load_dir "${CUSTOM_DIR}" "custom images"

log_info ""
log_info "Verifying loaded images:"
$CT_IMAGES --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}" 2>/dev/null || \
    $CT_IMAGES 2>/dev/null | head -40
log_ok "Image load complete. Ready for offline deployment."

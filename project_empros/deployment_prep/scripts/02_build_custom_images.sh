#!/usr/bin/env bash
# ==============================================================================
# 02_build_custom_images.sh
# Build all custom Nexus images from local Dockerfiles, then save them as
# compressed tarballs into deployment_prep/custom-images/.
#
# Run on: internet-connected machine (ONLINE phase, after script 01 so all
#         base images are available -- this script loads them before building).
# Output: deployment_prep/custom-images/<name>.tar.gz
#
# Manifest fields consumed:
#   name          -- image tag component (nexus-local/<name>:prep)
#   build_context -- path relative to REPO_ROOT ('.' for Rust workspace services,
#                   service subdir for Python/Node)
#   dockerfile    -- path to Dockerfile relative to build_context (default: Dockerfile)
#   build_args    -- optional JSON object of ARG=VALUE pairs passed as --build-arg
#   save_as       -- output archive filename
#
# WHY build_context matters for Rust services:
#   All Rust service Dockerfiles do 'COPY . .' and run 'cargo build -p <svc>'.
#   The service Cargo.toml uses '{ workspace = true }' which requires the
#   workspace-root Cargo.toml and Cargo.lock. If build_context is the service
#   subdirectory alone, the workspace root is absent and cargo fails to resolve
#   dependencies. build_context must be '.' (repo root) for Rust services.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PREP_DIR}/.." && pwd)"

source "${SCRIPT_DIR}/lib_container.sh"

MANIFEST="${PREP_DIR}/image_manifest.json"
IMAGES_DIR="${PREP_DIR}/images"
CUSTOM_DIR="${PREP_DIR}/custom-images"
mkdir -p "${CUSTOM_DIR}"

# -- Phase 2a: Load base images into the container store -----------------------
# Script 01 saves base images to images/*.tar.gz but does NOT load them into
# the local container runtime. If the machine was rebooted between Phase 1 and
# Phase 2, or if this is a fresh CI runner with the artifacts restored from
# cache, the base images must be loaded before docker build can use them.
# Without this step, every 'docker build' re-pulls base images from the internet.
load_base_images() {
    local loaded=0 skipped=0
    [[ -d "${IMAGES_DIR}" ]] || { log_warn "  images/ dir not found -- skipping pre-load"; return 0; }

    log_info "  Pre-loading base images from ${IMAGES_DIR}/ ..."
    while IFS= read -r archive; do
        [[ -z "${archive}" ]] && continue
        local name; name="$(basename "${archive}" .tar.gz)"
        # Check if this image is already loaded (skip re-load for speed)
        if gzip -t "${archive}" 2>/dev/null && \
           gzip -dc "${archive}" 2>/dev/null | $CT_LOAD --quiet 2>/dev/null; then
            (( loaded++ )) || true
        else
            log_warn "  Could not load ${name} -- will re-pull at build time"
            (( skipped++ )) || true
        fi
    done < <(find "${IMAGES_DIR}" -maxdepth 1 -name "*.tar.gz" | sort)

    log_ok "  Pre-loaded ${loaded} base image(s) (${skipped} skipped)"
}

# -- Parse manifest: emit name|context_rel|dockerfile_rel|save_as|build_args --
parse_custom() {
    python3 - "${MANIFEST}" <<'EOF'
import json, sys

data = json.load(open(sys.argv[1]))
for img in data.get("custom_images", []):
    # Skip comment-only entries
    if "_comment" in img and "name" not in img:
        continue
    name      = img.get("name", "")
    context   = img.get("build_context", "")
    dockerfile = img.get("dockerfile", "Dockerfile")
    save_as   = img.get("save_as", "")
    # Flatten build_args dict to "KEY=VALUE KEY2=VALUE2" string
    raw_args  = img.get("build_args", {}) or {}
    build_arg_str = " ".join(f"{k}={v}" for k, v in raw_args.items())
    if name and context and save_as:
        print(f"{name}|{context}|{dockerfile}|{save_as}|{build_arg_str}")
EOF
}

build_and_save() {
    local name="$1"
    local context_rel="$2"
    local dockerfile_rel="$3"
    local save_as="$4"
    local build_arg_str="$5"   # space-separated KEY=VALUE pairs (may be empty)

    # Resolve context: '.' means REPO_ROOT; otherwise it's relative to REPO_ROOT
    local context
    if [[ "${context_rel}" == "." ]]; then
        context="${REPO_ROOT}"
    else
        context="${REPO_ROOT}/${context_rel}"
    fi

    # Dockerfile path -- relative to build context
    local dockerfile="${context}/${dockerfile_rel}"

    local dest="${CUSTOM_DIR}/${save_as}"

    if [[ ! -d "${context}" ]]; then
        log_warn "  Build context not found, skipping: ${context}"
        return 0
    fi
    if [[ ! -f "${dockerfile}" ]]; then
        log_warn "  Dockerfile not found at ${dockerfile}, skipping: ${name}"
        return 0
    fi
    if [[ -f "${dest}" ]]; then
        log_warn "  Already exists, skipping: ${save_as}"
        return 0
    fi

    # Assemble --build-arg flags
    local build_arg_flags=()
    if [[ -n "${build_arg_str}" ]]; then
        while IFS= read -r pair; do
            [[ -n "${pair}" ]] && build_arg_flags+=("--build-arg" "${pair}")
        done < <(tr ' ' '\n' <<< "${build_arg_str}")
    fi

    log_info "  Building: ${name}"
    log_info "    context:    ${context_rel}"
    log_info "    dockerfile: ${dockerfile_rel}"
    [[ ${#build_arg_flags[@]} -gt 0 ]] && log_info "    build-args: ${build_arg_str}"

    if ! $CT_BUILD \
            --file "${dockerfile}" \
            --tag "nexus-local/${name}:prep" \
            "${build_arg_flags[@]+"${build_arg_flags[@]}"}" \
            "${context}"; then
        log_error "  FAILED to build: ${name}"
        return 1
    fi

    log_info "  Saving:   nexus-local/${name}:prep → ${save_as}"
    local tmp="${dest%.gz}"
    $CT_SAVE "nexus-local/${name}:prep" -o "${tmp}"
    gzip -9 "${tmp}"
    $CT_RMI "nexus-local/${name}:prep" 2>/dev/null || true
    log_ok "  Saved:    ${save_as} ($(du -sh "${dest}" | cut -f1))"
}

# -- Main ----------------------------------------------------------------------

log_info "=== Phase 2a: Pre-load base images into ${CONTAINER_RT} store ==="
load_base_images

log_info ""
log_info "=== Phase 2b: Build + Save Custom Images ==="
FAILED=()
while IFS='|' read -r name context dockerfile save_as build_args; do
    [[ -z "${name}" ]] && continue
    build_and_save "${name}" "${context}" "${dockerfile}" "${save_as}" "${build_args}" \
        || FAILED+=("${name}")
done < <(parse_custom)

log_info ""
TOTAL=$(ls "${CUSTOM_DIR}"/*.tar.gz 2>/dev/null | wc -l)
log_ok "  ${TOTAL} custom image archive(s) in ${CUSTOM_DIR}/"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    log_error "  ${#FAILED[@]} build(s) failed: ${FAILED[*]}"
    exit 1
fi
log_ok "All custom images built and saved successfully."

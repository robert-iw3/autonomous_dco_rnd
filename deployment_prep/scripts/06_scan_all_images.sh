#!/usr/bin/env bash
# ==============================================================================
# 06_scan_all_images.sh
# Run syft (SBOM) + grype (vulnerability) scans on all images using the
# Anchore scanner container. Reports land in deployment_prep/scan/reports/.
#
# Supports docker or podman (auto-detected via lib_container.sh).
# Optionally pass --runtime docker|podman to override.
#
# Run on: internet-connected machine after images are pulled (ONLINE phase),
#         OR on any machine with images already loaded.
# Output: deployment_prep/scan/reports/<image>_SBOM.{json,csv}
#                                      <image>_vulnerabilities.{json,csv}
#                                      scan_summary.json
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCAN_DIR="${PREP_DIR}/scan"
REPORTS_DIR="${SCAN_DIR}/reports"

source "${SCRIPT_DIR}/lib_container.sh"

RUNTIME_OVERRIDE=""
MAX_WORKERS=4
for arg in "$@"; do
    case "$arg" in
        --runtime=*) RUNTIME_OVERRIDE="${arg#*=}" ;;
        --workers=*)  MAX_WORKERS="${arg#*=}"     ;;
        --runtime)   shift; RUNTIME_OVERRIDE="$1" ;;
        --workers)   shift; MAX_WORKERS="$1"     ;;
    esac
done

[[ -n "$RUNTIME_OVERRIDE" ]] && export NEXUS_CONTAINER_RUNTIME="$RUNTIME_OVERRIDE"

mkdir -p "${REPORTS_DIR}"

log_info "=== Phase 6: Syft + Grype Image Scans ==="
log_info "  Reports dir:  ${REPORTS_DIR}"
log_info "  Runtime:      ${CONTAINER_RT}"
log_info "  Max workers:  ${MAX_WORKERS}"

# Ensure Python deps for the scanner are available
if ! python3 -c "import tqdm" &>/dev/null; then
    log_info "  Installing scan deps..."
    python3 -m pip install -q -r "${SCAN_DIR}/requirements.txt"
fi

pushd "${SCAN_DIR}" > /dev/null

python3 deploy_anchore.py \
    --runtime    "${CONTAINER_RT}" \
    --config     scan_config.json \
    --output-dir "${REPORTS_DIR}" \
    --max-workers "${MAX_WORKERS}"

popd > /dev/null

# Count results
N_SBOM=$(ls "${REPORTS_DIR}"/*_SBOM.json 2>/dev/null | wc -l)
N_VULN=$(ls "${REPORTS_DIR}"/*_vulnerabilities.json 2>/dev/null | wc -l)
log_ok "Scans complete: ${N_SBOM} SBOMs, ${N_VULN} vulnerability reports in ${REPORTS_DIR}/"

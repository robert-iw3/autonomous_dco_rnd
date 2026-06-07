#!/usr/bin/env bash
# ==============================================================================
# 07_hash_and_manifest.sh
# Generate SHA-256 hashes for every file in the bundle artifact directories,
# and produce a deployment_manifest.json cataloguing the full bundle contents.
#
# Run on: internet-connected machine after all download/scan/build phases.
# Output: deployment_prep/manifests/sha256sums.txt
#         deployment_prep/manifests/deployment_manifest.json
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFESTS_DIR="${PREP_DIR}/manifests"
mkdir -p "${MANIFESTS_DIR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "${CYAN}[hash]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[+]${NC} $*"; }

SHA_FILE="${MANIFESTS_DIR}/sha256sums.txt"
MANIFEST_FILE="${MANIFESTS_DIR}/deployment_manifest.json"

# Directories to hash (skip manifests/ to avoid self-referential hash)
ARTIFACT_DIRS=(
    "${PREP_DIR}/images"
    "${PREP_DIR}/custom-images"
    "${PREP_DIR}/wheels"
    "${PREP_DIR}/collections"
    "${PREP_DIR}/providers"
    "${PREP_DIR}/scan/reports"
)

log_info "=== Phase 7: SHA-256 Hash + Manifest Generation ==="

> "${SHA_FILE}"

for dir in "${ARTIFACT_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    rel="${dir#${PREP_DIR}/}"
    log_info "  Hashing: ${rel}/"
    while IFS= read -r -d '' file; do
        rel_file="${file#${PREP_DIR}/}"
        sha256sum "$file" | awk -v f="$rel_file" '{print $1 "  " f}' >> "${SHA_FILE}"
    done < <(find "$dir" -type f \( -name "*.tar.gz" -o -name "*.json" -o -name "*.csv" -o -name "*.whl" \) -print0 | sort -z)
done

TOTAL_HASHES=$(wc -l < "${SHA_FILE}")
log_ok "  ${TOTAL_HASHES} file(s) hashed → ${SHA_FILE}"

# Build deployment_manifest.json
python3 - "${PREP_DIR}" "${MANIFESTS_DIR}" <<'PYEOF'
import json, os, hashlib, sys
from pathlib import Path
from datetime import datetime

prep_dir = Path(sys.argv[1])
manifests_dir = Path(sys.argv[2])

sections = {
    "runtime_images":      "images",
    "custom_images":       "custom-images",
    "python_wheels":       "wheels",
    "ansible_collections": "collections",
    "terraform_providers": "providers",
    "scan_reports":        "scan/reports",
}

manifest = {
    "generated":  datetime.now().isoformat(),
    "prep_dir":   str(prep_dir),
    "sections":   {},
    "totals":     {},
}

for section, subdir in sections.items():
    d = prep_dir / subdir
    files = []
    if d.is_dir():
        for f in sorted(d.rglob("*")):
            if f.is_file():
                stat = f.stat()
                h = hashlib.sha256(f.read_bytes()).hexdigest()
                files.append({
                    "name":      f.name,
                    "path":      str(f.relative_to(prep_dir)),
                    "size_bytes": stat.st_size,
                    "sha256":    h,
                })
    manifest["sections"][section] = files
    manifest["totals"][section]   = {"count": len(files), "size_bytes": sum(f["size_bytes"] for f in files)}

out = manifests_dir / "deployment_manifest.json"
out.write_text(json.dumps(manifest, indent=2))
print(f"Manifest: {out}")
for sec, totals in manifest["totals"].items():
    if totals["count"]:
        size_mb = round(totals["size_bytes"] / 1024 / 1024, 1)
        print(f"  {sec}: {totals['count']} file(s) ({size_mb} MB)")
PYEOF

log_ok "Manifest written → ${MANIFEST_FILE}"

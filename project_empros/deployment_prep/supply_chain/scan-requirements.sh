#!/usr/bin/env bash
# ==============================================================================
# supply_chain/scan-requirements.sh
# Standalone GuardDog supply-chain scanner.
# Scans the CANONICAL Python requirements list (../python_requirements.txt)
# via GuardDog running inside a hardened container.
#
# REQUIREMENTS_FILE defaults to the central canonical list. Override to scan
# a specific file:
#   REQUIREMENTS_FILE=/path/to/requirements.txt bash scan-requirements.sh
#
# For automated bundle prep use 05c_scan_python_supply_chain.sh instead;
# this script is for ad-hoc/interactive use.
# ==============================================================================
set -e

SC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP_DIR="$(cd "${SC_DIR}/.." && pwd)"

IMAGE_NAME="local/nexus-guarddog-scanner:latest"
# Default: canonical central list; override via env var
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-${PREP_DIR}/python_requirements.txt}"
CONFIG_FILE="${SC_DIR}/guarddog-config.yaml"
OUTPUT_FILE="${SC_DIR}/guarddog_scan_results.txt"

if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
    echo "[!] Requirements file not found: ${REQUIREMENTS_FILE}"
    echo "    Set REQUIREMENTS_FILE env var or ensure python_requirements.txt exists."
    exit 1
fi

rm -f "${OUTPUT_FILE}"
touch "${OUTPUT_FILE}"

echo "=== [1/3] Building GuardDog Image ==="
podman build -t "${IMAGE_NAME}" .

echo "=== [2/3] Scanning packages from: ${REQUIREMENTS_FILE} ==="

mapfile -t packages < <(grep -vE '^\s*(#|$|-r |-c |-e |--|-f )' "${REQUIREMENTS_FILE}" \
    | sed 's/[=><!;@ ].*$//' \
    | sed 's/\[.*\]$//' \
    | grep -vE '^\s*$' \
    | sort -u)

for pkg in "${packages[@]}"; do
    pkg_name=$(echo "${pkg}" | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1)

    echo "Scanning ${pkg_name}..."

    podman run --rm \
      --network none \
      -v "${CONFIG_FILE}:/workspace/${CONFIG_FILE##*/}:ro" \
      "${IMAGE_NAME}" /venv/bin/guarddog pypi scan "${pkg_name}" \
      --config "/workspace/${CONFIG_FILE##*/}" >> "${OUTPUT_FILE}" 2>&1 || \
    echo "WARNING: Scan for ${pkg_name} exited with non-zero code." >> "${OUTPUT_FILE}"

    sleep 2
done

echo "=== [3/3] Scan Complete ==="
echo "Full report: ${OUTPUT_FILE}"
echo "Scanned ${#packages[@]} packages from ${REQUIREMENTS_FILE}"

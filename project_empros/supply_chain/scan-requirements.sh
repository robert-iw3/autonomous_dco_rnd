#!/usr/bin/env bash
set -e

IMAGE_NAME="local/guarddog-scanner:latest"
REQUIREMENTS_FILE="requirements.txt"
CONFIG_FILE="guarddog-config.yaml"
OUTPUT_FILE="guarddog_scan_results.txt"

rm -f "$OUTPUT_FILE"
touch "$OUTPUT_FILE"

echo "=== [1/3] Building GuardDog Image ==="
podman build -t "$IMAGE_NAME" .

echo "=== [2/3] Scanning packages individually ==="

mapfile -t packages < <(grep -vE '^\s*($|#)' "$REQUIREMENTS_FILE")

for pkg in "${packages[@]}"; do
    pkg_name=$(echo "$pkg" | cut -d'=' -f1 | cut -d'>' -f1)

    echo "Scanning $pkg_name..."

    podman run --rm \
      -v "$(pwd)/$CONFIG_FILE:/workspace/$CONFIG_FILE:ro" \
      "$IMAGE_NAME" /venv/bin/guarddog pypi scan "$pkg_name" \
      --config "/workspace/$CONFIG_FILE" >> "$OUTPUT_FILE" 2>&1 || \
    echo "WARNING: Scan for $pkg_name exited with non-zero code." >> "$OUTPUT_FILE"

    sleep 2
done

echo "=== [3/3] Scan Complete ==="
echo "Full report: $(pwd)/$OUTPUT_FILE"
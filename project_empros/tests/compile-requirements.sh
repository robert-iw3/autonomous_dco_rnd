#!/usr/bin/env bash
set -e

echo "[*] Spinning up ephemeral compiler container..."

podman run --rm -it \
  -v "$(pwd):/workspace:Z" \
  -w /workspace \
  python:3.11-slim \
  sh -c "pip install --upgrade pip && pip install --no-cache-dir pip-tools && pip-compile --generate-hashes requirements.in"

echo "[+] Compilation complete. requirements.txt is now locked."
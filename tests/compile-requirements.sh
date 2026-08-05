#!/usr/bin/env bash
set -e

echo "[*] Spinning up ephemeral compiler container..."

podman run --rm -it \
  -v "$(pwd):/workspace:Z" \
  -w /workspace \
  python:3.11-slim \
  sh -c "pip install --upgrade 'pip<26' && pip install --no-cache-dir pip-tools==7.6.0 && pip-compile --generate-hashes --allow-unsafe --upgrade requirements.in"

echo "[+] Compilation complete. requirements.txt is now locked."
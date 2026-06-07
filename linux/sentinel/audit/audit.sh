#!/usr/bin/env bash
set -e

AUDITOR_IMAGE="rust-auditor:latest"
REPORT="rust_audit_report.txt"

echo "=============================================" > "$REPORT"
echo "  Rust Security Audit - $(date)" >> "$REPORT"
echo "=============================================" >> "$REPORT"

echo "[*] Building Audit Container Image..."
podman build -t "$AUDITOR_IMAGE" -f audit.Dockerfile .

echo "[*] Initializing Rust Supply Chain Audit..."

find .. -name "Cargo.toml" | while read -r cargo_toml; do

    service_path=$(dirname "$cargo_toml")
    service_name=$(basename "$service_path")

    echo "[+] Auditing service: $service_name"
    rm -f "$service_path/Cargo.lock"

    echo "" >> "$REPORT"
    echo "---------------------------------------------" >> "$REPORT"
    echo "  $service_name" >> "$REPORT"
    echo "---------------------------------------------" >> "$REPORT"

    podman run --rm \
        -v "$(pwd):/audit/services:Z" \
        -v "$(pwd)/../:/audit/:Z" \
        -w "/audit/services/$service_path" \
        "$AUDITOR_IMAGE" \
        sh -c "cargo generate-lockfile && cargo audit" >> "$REPORT" 2>&1 | sed "s/^/[$service_name]: /"

done

echo "" >> "$REPORT"
echo "=============================================" >> "$REPORT"
echo "  Audit Complete" >> "$REPORT"
echo "=============================================" >> "$REPORT"

echo "[+] Audit complete. Report saved to $REPORT"
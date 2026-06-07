#!/usr/bin/env bash
# ==============================================================================
# Sentinel Nexus -- Rust Supply Chain Audit
#
# Audits the entire workspace from the root Cargo.toml as a single dependency
# tree. All services and middleware share one Cargo.lock, so one audit run
# covers the full crate graph and eliminates version-drift between services.
#
# Security pins enforced by root [workspace.dependencies] (see Cargo.toml):
#   async-nats  >= 0.48   RUSTSEC-2026-{0049,0098,0099,0104}
#   validator   >= 0.20   RUSTSEC-2024-0421
#   object_store >= 0.11  RUSTSEC-2024-0358
#   parquet     >= 53     RUSTSEC-2023-0086   (58.3 satisfies)
#
# Accepted-risk advisories are listed in .cargo/audit.toml with rationale.
# cargo-audit reads that file automatically from the workspace root.
# ==============================================================================
set -euo pipefail

AUDITOR_IMAGE="rust-auditor:latest"
REPORT="rust_audit_report.txt"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

{
    echo "============================================="
    echo "  Rust Security Audit - $(date)"
    echo "  Workspace: $REPO_ROOT"
    echo "============================================="
} > "$REPORT"

echo "[*] Building audit container image..."
podman build -q -t "$AUDITOR_IMAGE" -f "$REPO_ROOT/audit.Dockerfile" "$REPO_ROOT"

echo "[*] Running workspace-level cargo audit..."
{
    echo ""
    echo "---------------------------------------------"
    echo "  Full Workspace (root Cargo.toml)"
    echo "---------------------------------------------"
} >> "$REPORT"

AUDIT_EXIT=0
podman run --rm \
    -v "${REPO_ROOT}:/audit/workspace:Z" \
    -w "/audit/workspace" \
    "$AUDITOR_IMAGE" \
    sh -c "cargo generate-lockfile 2>&1 && cargo audit 2>&1" >> "$REPORT" || AUDIT_EXIT=$?

{
    echo ""
    echo "============================================="
    echo "  Audit Complete (exit: $AUDIT_EXIT)"
    echo "============================================="
} >> "$REPORT"

echo "[+] Report written to $REPORT"

# cargo audit exits 1 on unignored vulnerabilities.
# Warnings from .cargo/audit.toml ignore list are allowed through.
if grep -q "^error:" "$REPORT"; then
    echo "[!] CRITICAL: Unacknowledged vulnerability found. Review $REPORT immediately."
    exit 1
elif [ "$AUDIT_EXIT" -ne 0 ]; then
    echo "[!] Audit container exited $AUDIT_EXIT -- check $REPORT for details."
    exit "$AUDIT_EXIT"
else
    WARN_COUNT=$(grep -c "^warning:" "$REPORT" 2>/dev/null || true)
    echo "[+] Clean. ${WARN_COUNT} accepted residual warning(s) -- rationale in .cargo/audit.toml."
fi

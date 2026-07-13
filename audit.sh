#!/usr/bin/env bash
# ==============================================================================
# Sentinel Nexus -- Rust Supply Chain Audit
#
# Two audit passes -- the repo holds TWO independent Cargo workspaces:
#   1. Root workspace (Cargo.toml): libs/ + services/ + tests/integration
#   2. Middleware workspace (middleware/Cargo.toml): ETL fan-out layer
# Each has its own Cargo.lock; auditing only the root (the previous behaviour)
# left every middleware crate unaudited.
#
# The committed Cargo.lock is what build.sh compiles, so the audit runs against
# it directly (--locked semantics). A lockfile is generated only if missing.
#
# Security pins enforced by [workspace.dependencies] (see both Cargo.toml):
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

# run_audit <workspace-subdir> <label>
# Audits the committed Cargo.lock; generates one only if absent.
run_audit() {
    local subdir="$1" label="$2" exit_code=0
    {
        echo ""
        echo "---------------------------------------------"
        echo "  ${label}"
        echo "---------------------------------------------"
    } >> "$REPORT"
    podman run --rm \
        -v "${REPO_ROOT}:/audit/workspace:Z" \
        -w "/audit/workspace/${subdir}" \
        "$AUDITOR_IMAGE" \
        sh -c "[ -f Cargo.lock ] || cargo generate-lockfile 2>&1; cargo audit 2>&1" \
        >> "$REPORT" || exit_code=$?
    return $exit_code
}

AUDIT_EXIT=0
echo "[*] Pass 1/2: root workspace (libs + services)..."
run_audit "." "Root Workspace (Cargo.toml: libs/ + services/)" || AUDIT_EXIT=$?

echo "[*] Pass 2/2: middleware workspace..."
run_audit "middleware" "Middleware Workspace (middleware/Cargo.toml)" || AUDIT_EXIT=$?

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

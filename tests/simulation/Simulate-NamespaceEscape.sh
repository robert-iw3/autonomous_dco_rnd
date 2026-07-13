#!/bin/bash
# ==============================================================================
# Playbook 6: Linux Namespace Escape Simulation (T1611)
#
# Validates that:
#   1. Linux Sentinel eBPF hooks catch the unshare(2) call
#   2. worker_rules matches the T1611 Sigma rule
#   3. Alert arrives with source_type: linux_sentinel, vector_name: sentinel_math
#   4. The 5D sentinel_math vector is correctly routed (not c2_math or windows_math)
#   5. is_internal_dst is true (namespace escapes are local)
# ==============================================================================

set -euo pipefail

REDIS_CLI="${REDIS_CLI:-redis-cli}"
REDIS_URL="${REDIS_URL:-redis://redis:6379}"

echo -e "\033[1;36m[*] Initiating Linux Namespace Escape Simulation (T1611)...\033[0m"

echo -e "\033[1;33m[!] Executing 'unshare' to detach from mount and PID namespaces...\033[0m"
echo "    -> Expected routing: source_type=linux_sentinel | vector_name=sentinel_math (5D)"
echo "    -> Expected derived: is_internal_dst=true (localhost)"

# This command aggressively alters namespaces, triggering the eBPF anomaly detection
# and the hardcoded Linux Sentinel AST rule for T1611.
unshare -m -u -i -n -p -f --mount-proc /bin/bash -c \
    "echo 'Inside simulated rootkit namespace'; whoami; hostname; exit" 2>/dev/null || true

echo -e "\033[1;32m[+] Evasion simulation complete.\033[0m"

# ── Post-Detonation Validation ──
echo ""
echo -e "\033[1;33m[*] Running post-detonation checks...\033[0m"

# Check Redis for the alert with correct metadata
ALERT_CHECK=$($REDIS_CLI -u "$REDIS_URL" GET "nexus:qdrant:alerts:latest" 2>/dev/null || echo "REDIS_UNAVAILABLE")

if [ "$ALERT_CHECK" = "REDIS_UNAVAILABLE" ]; then
    echo "    -> Redis unavailable. Manual validation required."
    echo "    -> Check: redis-cli GET nexus:qdrant:alerts:latest"
else
    echo "    -> Alert payload from Redis:"

    # Validate source_type
    if echo "$ALERT_CHECK" | grep -q '"source_type":"linux_sentinel"' 2>/dev/null; then
        echo "    -> [PASS] source_type: linux_sentinel"
    else
        echo "    -> [CHECK] Verify source_type is 'linux_sentinel' (not windows_c2 or network_tap)"
    fi

    # Validate vector_name
    if echo "$ALERT_CHECK" | grep -q '"vector_name":"sentinel_math"' 2>/dev/null; then
        echo "    -> [PASS] vector_name: sentinel_math (5D)"
    else
        echo "    -> [CHECK] Verify vector_name is 'sentinel_math' (not c2_math)"
    fi
fi

echo ""
echo "Validation checklist:"
echo "  [ ] Redis queue has T1611 rule match"
echo "  [ ] source_type = linux_sentinel"
echo "  [ ] vector_name = sentinel_math"
echo "  [ ] Qdrant KEYWORD index filters to sentinel_math named vector"
echo "  [ ] Orchestrator routes to host_expert (Linux process forensics)"
echo "  [ ] is_internal_dst = true (namespace operations are local)"
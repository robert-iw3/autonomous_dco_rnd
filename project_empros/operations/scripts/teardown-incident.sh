#!/usr/bin/env bash
# ==============================================================================
# Sentinel Nexus -- Ephemeral Teardown & Scorched-Earth Purge
# Gracefully shuts down all stacks, verifies cleanup, optionally purges secrets.
# ==============================================================================

source "$(dirname "$0")/lib.sh"

EVENT_ID="${1:-UNKNOWN}"
DEEP_CLEAN="${2:-}"   # Pass --deep to also remove .env, certs, and network

log_step "Ephemeral Teardown: ${EVENT_ID}"

# -- 1. Tear down in reverse dependency order --
log_step "Stack Teardown (reverse order)"
compose_down "$OPS_ROOT/webui/docker-compose.yml" "webui"
compose_down "$OPS_ROOT/n8n/docker-compose.yml"   "n8n"
compose_down "$OPS_ROOT/infra/docker-compose.yml"  "infra"

# -- 2. Verify all nexus containers are stopped --
log_step "Container Verification"
verify_containers_stopped "$NEXUS_STACK_PREFIX"
log_ok "All ${NEXUS_STACK_PREFIX} containers confirmed stopped."

# -- 3. Clean ephemeral context data --
log_step "Ephemeral Data Cleanup"
if [[ -f "$OPS_ROOT/webui/data/workspace_context.json" ]]; then
    rm -f "$OPS_ROOT/webui/data/workspace_context.json"
    log_ok "Incident context file purged."
fi

# Clean n8n execution logs
if [[ -d "$OPS_ROOT/n8n/logs" ]]; then
    rm -rf "$OPS_ROOT/n8n/logs"/*
    log_ok "n8n execution logs purged."
fi

# -- 4. Deep Clean (optional) --
if [[ "$DEEP_CLEAN" == "--deep" ]]; then
    log_step "Deep Clean Mode"

    # Remove .env secrets
    if [[ -f "$NEXUS_ENV_FILE" ]]; then
        # Secure overwrite before deletion
        dd if=/dev/urandom of="$NEXUS_ENV_FILE" bs=1k count=1 2>/dev/null || true
        rm -f "$NEXUS_ENV_FILE" "${NEXUS_ENV_FILE}.bak."*
        log_ok "Secrets file securely wiped."
    fi

    # Remove TLS material
    if [[ -d "$NEXUS_TLS_DIR" ]]; then
        sudo rm -rf "$NEXUS_TLS_DIR"
        log_ok "TLS certificates and CA purged."
    fi

    # Remove the network
    if podman network inspect "$NEXUS_NETWORK_NAME" &>/dev/null; then
        podman network rm "$NEXUS_NETWORK_NAME" 2>/dev/null || true
        log_ok "Network ${NEXUS_NETWORK_NAME} removed."
    fi

    log_warn "Deep clean complete. Re-run env-gen.sh and cert-gen.sh before next deployment."
fi

# -- 5. Audit Log --
log_step "Teardown Summary"
log_ok "Incident ${EVENT_ID} -- attack surface returned to zero."
log_info "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log_info "Deep clean: ${DEEP_CLEAN:-no}"
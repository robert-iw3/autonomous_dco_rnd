#!/usr/bin/env bash
# ==============================================================================
# Sentinel Nexus -- Incident Trigger & Ephemeral Stack Bootstrap
# Validates prerequisites, injects context, and deploys the full C&C stack.
# ==============================================================================

source "$(dirname "$0")/lib.sh"
trap 'on_error_cleanup' ERR

# -- Argument Parsing --
EVENT_ID="${1:-}"
SKIP_CONTEXT="${SKIP_CONTEXT:-false}"

if [[ -z "$EVENT_ID" ]]; then
    log_fatal "Usage: $0 <EVENT_ID> [--skip-context]"
fi
if [[ "${2:-}" == "--skip-context" ]]; then
    SKIP_CONTEXT="true"
fi

log_step "Incident Trigger: ${EVENT_ID}"

# -- 1. Pre-flight --
preflight_check
validate_env_file
validate_tls

# Source the .env so S3 keys are available
set -a
source "$NEXUS_ENV_FILE"
set +a

# -- 2. Network --
log_step "Network Bootstrap"
ensure_network

# -- 3. Context Injection via DuckDB --
log_step "Context Injection"

CONTEXT_DIR="$OPS_ROOT/webui/data"
CONTEXT_FILE="$CONTEXT_DIR/workspace_context.json"
mkdir -p "$CONTEXT_DIR"

if [[ "$SKIP_CONTEXT" == "true" ]]; then
    log_warn "Context injection skipped (--skip-context). Writing empty context."
    echo "{\"incident_id\": \"${EVENT_ID}\", \"context\": [], \"note\": \"Context injection skipped by operator\"}" > "$CONTEXT_FILE"
else
    log_info "Extracting incident context for ${EVENT_ID} from S3 Data Lake..."
    if ! python3 -c "
import duckdb, json, os, sys
try:
    con = duckdb.connect()
    con.execute('INSTALL httpfs; LOAD httpfs;')
    con.execute(\"\"\"
        SET s3_endpoint='${NEXUS_S3_ENDPOINT}';
        SET s3_access_key_id='${NEXUS_S3_ACCESS_KEY}';
        SET s3_secret_access_key='${NEXUS_S3_SECRET_KEY}';
        SET s3_use_ssl=${NEXUS_S3_USE_SSL};
        SET s3_url_style='${NEXUS_S3_URL_STYLE}';
    \"\"\")
    df = con.execute(
        f\"SELECT * FROM 's3://${NEXUS_S3_BUCKET}/${NEXUS_S3_TELEMETRY_PATH}' WHERE event_id = '\${EVENT_ID}'\"
    ).fetchdf()
    context = df.to_dict(orient='records') if not df.empty else []
    payload = {
        'incident_id': '${EVENT_ID}',
        'record_count': len(context),
        'context': context
    }
    with open('${CONTEXT_FILE}', 'w') as f:
        json.dump(payload, f, default=str)
    print(f'Extracted {len(context)} context records.')
    sys.exit(0)
except Exception as e:
    print(f'Context extraction failed: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1; then
        log_warn "DuckDB context extraction failed. Deploying with empty context."
        echo "{\"incident_id\": \"${EVENT_ID}\", \"context\": [], \"error\": \"extraction_failed\"}" > "$CONTEXT_FILE"
    fi
fi

# -- 4. Deploy Core Infrastructure --
log_step "Core Infrastructure (Ingress + SSO)"
compose_up "$OPS_ROOT/infra/docker-compose.yml" "infra"

# Wait for Postgres and Redis before checking Authentik
wait_for_container "${NEXUS_STACK_PREFIX}-sso-db" 60
wait_for_container "${NEXUS_STACK_PREFIX}-sso-cache" 30

# Wait for Authentik server to become ready
wait_for_health \
    "https://${NEXUS_DOMAIN_SSO}/-/health/ready/" \
    "Authentik Identity Provider" \
    "$NEXUS_HEALTH_TIMEOUT"

# -- 5. Deploy Operational Interfaces --
log_step "Operational Interfaces (n8n + WebUI)"
compose_up "$OPS_ROOT/n8n/docker-compose.yml" "n8n"
compose_up "$OPS_ROOT/webui/docker-compose.yml" "webui"

# Wait for interface containers
wait_for_container "${NEXUS_STACK_PREFIX}-n8n-ephemeral" "$NEXUS_HEALTH_TIMEOUT"
wait_for_container "${NEXUS_STACK_PREFIX}-webui-ephemeral" "$NEXUS_HEALTH_TIMEOUT"

# -- 6. Verify End-to-End Reachability --
log_step "End-to-End Verification"
wait_for_health "https://${NEXUS_DOMAIN_N8N}/healthz"  "n8n"    30
wait_for_health "https://${NEXUS_DOMAIN_WEBUI}/"        "WebUI"  30

# -- 7. Summary --
log_step "Deployment Complete"
log_ok "Incident: ${EVENT_ID}"
log_ok "Context records injected: $(python3 -c "import json; print(json.load(open('${CONTEXT_FILE}')).get('record_count', '?'))" 2>/dev/null || echo 'unknown')"
log_ok "Endpoints:"
log_info "  WebUI  → https://${NEXUS_DOMAIN_WEBUI}"
log_info "  n8n    → https://${NEXUS_DOMAIN_N8N}"
log_info "  SSO    → https://${NEXUS_DOMAIN_SSO}"
log_info "  Traefik Dashboard → https://${NEXUS_DOMAIN_INGRESS}:8080"
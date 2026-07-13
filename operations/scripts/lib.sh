#!/usr/bin/env bash
# ==============================================================================
# Sentinel Nexus -- Shared Shell Library
# Source this in every lifecycle script for logging, health checks, and guards.
# ==============================================================================

set -euo pipefail

# -- Resolve paths and load central config --
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")" && pwd)"
OPS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$OPS_ROOT/nexus.conf"

# -- ANSI Colors --
_RED='\033[0;31m'
_GREEN='\033[0;32m'
_YELLOW='\033[1;33m'
_CYAN='\033[0;36m'
_BOLD='\033[1m'
_RESET='\033[0m'

# -- Logging --
log_info()  { echo -e "${_CYAN}[*]${_RESET} $*"; }
log_ok()    { echo -e "${_GREEN}[+]${_RESET} $*"; }
log_warn()  { echo -e "${_YELLOW}[!]${_RESET} $*" >&2; }
log_error() { echo -e "${_RED}[✗]${_RESET} $*" >&2; }
log_fatal() { log_error "$@"; exit 1; }
log_step()  { echo -e "\n${_BOLD}-- $* --${_RESET}"; }

# -- Dependency Checks --
require_cmd() {
    local cmd="$1"
    command -v "$cmd" &>/dev/null || log_fatal "Required command not found: ${cmd}. Install it and retry."
}

preflight_check() {
    log_step "Pre-flight Checks"
    local deps=("podman" "podman-compose" "openssl" "curl" "python3")
    for cmd in "${deps[@]}"; do
        require_cmd "$cmd"
    done
    log_ok "All required tools present."
}

# -- Network Bootstrap --
ensure_network() {
    if ! podman network inspect "$NEXUS_NETWORK_NAME" &>/dev/null; then
        log_info "Creating bridge network: ${NEXUS_NETWORK_NAME} (${NEXUS_NETWORK_SUBNET})"
        podman network create \
            --driver bridge \
            --subnet "$NEXUS_NETWORK_SUBNET" \
            --gateway "$NEXUS_NETWORK_GATEWAY" \
            "$NEXUS_NETWORK_NAME"
        log_ok "Network created."
    else
        log_ok "Network ${NEXUS_NETWORK_NAME} already exists."
    fi
}

# -- Health Checks --
# wait_for_health URL [LABEL] [TIMEOUT] [INTERVAL]
# Polls a URL until it returns HTTP 2xx. Fatals on timeout.
wait_for_health() {
    local url="$1"
    local label="${2:-$1}"
    local timeout="${3:-$NEXUS_HEALTH_TIMEOUT}"
    local interval="${4:-$NEXUS_HEALTH_INTERVAL}"
    local elapsed=0

    log_info "Waiting for ${label} to become healthy (timeout: ${timeout}s)..."
    while (( elapsed < timeout )); do
        if curl -sf -k --max-time 5 "$url" &>/dev/null; then
            log_ok "${label} is healthy (${elapsed}s)."
            return 0
        fi
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
        printf "."
    done
    echo ""
    log_fatal "${label} did not become healthy within ${timeout}s. Aborting."
}

# wait_for_container CONTAINER_NAME [TIMEOUT]
# Waits until a container reports 'healthy' via podman inspect.
wait_for_container() {
    local name="$1"
    local timeout="${2:-$NEXUS_HEALTH_TIMEOUT}"
    local interval="$NEXUS_HEALTH_INTERVAL"
    local elapsed=0

    log_info "Waiting for container ${name} health check (timeout: ${timeout}s)..."
    while (( elapsed < timeout )); do
        local status
        status=$(podman inspect --format='{{.State.Health.Status}}' "$name" 2>/dev/null || echo "missing")
        case "$status" in
            healthy)
                log_ok "Container ${name} is healthy (${elapsed}s)."
                return 0
                ;;
            unhealthy)
                log_fatal "Container ${name} reported unhealthy."
                ;;
            missing)
                # Container might not exist yet
                ;;
        esac
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done
    log_fatal "Container ${name} did not become healthy within ${timeout}s."
}

# -- Compose Helpers --
compose_up() {
    local compose_file="$1"
    local label="${2:-$(basename "$(dirname "$compose_file")")}"
    log_info "Deploying stack: ${label}..."
    podman-compose -f "$compose_file" up -d --remove-orphans
    log_ok "Stack ${label} containers started."
}

compose_down() {
    local compose_file="$1"
    local label="${2:-$(basename "$(dirname "$compose_file")")}"
    if [[ -f "$compose_file" ]]; then
        log_info "Tearing down stack: ${label}..."
        podman-compose -f "$compose_file" down -v -t "$NEXUS_TEARDOWN_GRACE_PERIOD" 2>/dev/null || true
        log_ok "Stack ${label} purged."
    else
        log_warn "Compose file not found, skipping: ${compose_file}"
    fi
}

# -- Container Verification --
verify_containers_stopped() {
    local prefix="$1"
    local running
    running=$(podman ps --filter "name=${prefix}" --format "{{.Names}}" 2>/dev/null || true)
    if [[ -n "$running" ]]; then
        log_warn "Containers still running after teardown: ${running}"
        log_info "Force-removing stragglers..."
        echo "$running" | xargs -r podman rm -f 2>/dev/null || true
    fi
}

# -- .env Validation --
validate_env_file() {
    local env_file="${1:-$NEXUS_ENV_FILE}"
    [[ -f "$env_file" ]] || log_fatal ".env file not found at ${env_file}. Run scripts/env-gen.sh first."

    local missing=()
    local required_vars=(
        "N8N_ENCRYPTION_KEY"
        "WEBUI_SECRET_KEY"
        "JWT_SECRET"
        "PG_PASS"
        "OAUTH_CLIENT_ID"
        "OAUTH_CLIENT_SECRET"
    )
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" "$env_file" || grep -q "^${var}=replace_" "$env_file"; then
            missing+=("$var")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        log_fatal "Missing or placeholder values in ${env_file}: ${missing[*]}"
    fi
    log_ok ".env validated -- all required secrets present."
}

# -- TLS Validation --
validate_tls() {
    local tls_dir="${1:-$NEXUS_TLS_DIR}"
    [[ -f "$tls_dir/nexus-ca.crt" ]] || log_fatal "Root CA not found at ${tls_dir}/nexus-ca.crt. Run scripts/cert-gen.sh first."

    local domains=("$NEXUS_DOMAIN_N8N" "$NEXUS_DOMAIN_WEBUI")
    for domain in "${domains[@]}"; do
        local basename="${domain%%.*}"
        [[ -f "$tls_dir/${basename}.crt" ]] || log_fatal "TLS cert missing for ${domain}. Run scripts/cert-gen.sh."
        [[ -f "$tls_dir/${basename}.key" ]] || log_fatal "TLS key missing for ${domain}. Run scripts/cert-gen.sh."
    done
    log_ok "TLS certificates validated."
}

# -- Trap handler for cleanup on script failure --
# Usage: trap 'on_error_cleanup' ERR
on_error_cleanup() {
    local exit_code=$?
    log_error "Script failed with exit code ${exit_code}. Check logs above."
    exit "$exit_code"
}

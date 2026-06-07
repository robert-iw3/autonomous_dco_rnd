#!/usr/bin/env bash
# ==============================================================================
# lib_container.sh -- Container runtime abstraction layer
#
# Source this from every deployment_prep script:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib_container.sh"
#
# Sets:
#   CONTAINER_RT      -- "docker" or "podman"
#   COMPOSE_CMD       -- full compose command (e.g. "docker compose" or "podman compose")
#   CT_BUILD          -- build subcommand
#   CT_PULL           -- pull subcommand
#   CT_PUSH           -- push subcommand
#   CT_SAVE           -- save subcommand
#   CT_LOAD           -- load subcommand
#   CT_RUN            -- run subcommand
#   CT_EXEC           -- exec subcommand
#   CT_CP             -- cp subcommand
#   CT_RMI            -- rmi subcommand
#   CT_RM             -- rm subcommand
#   CT_PRUNE_IMAGES   -- image prune subcommand
#   CT_INSPECT        -- inspect subcommand
#   CT_TAG            -- tag subcommand
#   CT_IMAGES         -- images subcommand
# ==============================================================================

_detect_container_runtime() {
    # Prefer explicitly set override
    if [[ -n "${NEXUS_CONTAINER_RUNTIME:-}" ]]; then
        echo "$NEXUS_CONTAINER_RUNTIME"
        return
    fi

    # Prefer docker if both present (CI/CD environments typically have docker)
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        echo "docker"
    elif command -v podman &>/dev/null; then
        echo "podman"
    elif command -v docker &>/dev/null; then
        # docker present but daemon not running -- still set it (may work for some ops)
        echo "docker"
    else
        echo ""
    fi
}

_detect_compose_cmd() {
    local rt="$1"
    if [[ "$rt" == "docker" ]]; then
        if docker compose version &>/dev/null 2>&1; then
            echo "docker compose"
        elif command -v docker-compose &>/dev/null; then
            echo "docker-compose"
        else
            echo "docker compose"
        fi
    elif [[ "$rt" == "podman" ]]; then
        if command -v podman-compose &>/dev/null; then
            echo "podman-compose"
        elif podman compose version &>/dev/null 2>&1; then
            echo "podman compose"
        else
            echo "podman-compose"
        fi
    fi
}

# -- Initialise ----------------------------------------------------------------
CONTAINER_RT="$(_detect_container_runtime)"

if [[ -z "$CONTAINER_RT" ]]; then
    echo "[container-lib] ERROR: Neither docker nor podman found. Install one before proceeding." >&2
    exit 1
fi

COMPOSE_CMD="$(_detect_compose_cmd "$CONTAINER_RT")"

# Subcommand aliases -- identical syntax across docker and podman for these ops
CT_BUILD="$CONTAINER_RT build"
CT_PULL="$CONTAINER_RT pull"
CT_PUSH="$CONTAINER_RT push"
CT_SAVE="$CONTAINER_RT save"
CT_LOAD="$CONTAINER_RT load"
CT_RUN="$CONTAINER_RT run"
CT_EXEC="$CONTAINER_RT exec"
CT_CP="$CONTAINER_RT cp"
CT_RMI="$CONTAINER_RT rmi"
CT_RM="$CONTAINER_RT rm"
CT_TAG="$CONTAINER_RT tag"
CT_IMAGES="$CONTAINER_RT images"
CT_INSPECT="$CONTAINER_RT inspect"

# Image prune syntax is the same for both
CT_PRUNE_IMAGES="$CONTAINER_RT image prune -f"

# Export for sub-shells
export CONTAINER_RT COMPOSE_CMD
export CT_BUILD CT_PULL CT_PUSH CT_SAVE CT_LOAD CT_RUN CT_EXEC CT_CP
export CT_RMI CT_RM CT_PRUNE_IMAGES CT_INSPECT CT_TAG CT_IMAGES

# Color helpers (if not already defined by caller)
if [[ -z "${RED:-}" ]]; then
    RED='\033[0;31]'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
    log_info()  { echo -e "${CYAN}[${CONTAINER_RT}]${NC} $*"; }
    log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
    log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
    log_error() { echo -e "${RED}[!]${NC} $*" >&2; }
fi

log_info "Container runtime: ${BOLD}${CONTAINER_RT}${NC}  |  Compose: ${BOLD}${COMPOSE_CMD}${NC}"

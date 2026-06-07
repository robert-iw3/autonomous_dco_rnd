#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
cd "$SCRIPT_DIR" || { echo -e "\033[0;31m[ FAIL ]\033[0m Could not anchor to script directory"; exit 1; }

# Boot Tags
G='\033[0;32m'
R='\033[0;31m'
C='\033[0;36m'
N='\033[0m'
OK="[ ${G} OK ${N} ]"
FAIL="[ ${R}FAIL${N} ]"
INFO="[ ${C}INFO${N} ]"

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
  echo -e "${FAIL} Root privileges required"
  exit 1
fi
echo -e "${OK} Root privileges verified"

# 2. Dependencies
for cmd in openssl curl; do
  if ! command -v "$cmd" &> /dev/null; then
    echo -e "${FAIL} Missing dependency: $cmd"
    exit 1
  fi
done
echo -e "${OK} Dependencies verified"

# 3. Engine Detection
RUNTIME=""
COMPOSE_CMD=""

if command -v podman &> /dev/null; then
    RUNTIME="podman"
    if command -v podman-compose &> /dev/null; then COMPOSE_CMD="podman-compose"
    else COMPOSE_CMD="podman compose"; fi
elif command -v docker &> /dev/null; then
    RUNTIME="docker"
    if docker compose version &> /dev/null; then COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then COMPOSE_CMD="docker-compose"
    else
        echo -e "${FAIL} Docker found, but docker-compose missing"
        exit 1
    fi
else
    echo -e "${FAIL} Neither podman nor docker found"
    exit 1
fi
echo -e "${OK} Orchestration engine: $COMPOSE_CMD"

# 4. Certs
mkdir -p data certs
if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
    chmod +x deploy/generate_sensor_certs.sh 2>/dev/null || chmod +x generate_sensor_certs.sh 2>/dev/null

    if [ -f "deploy/generate_sensor_certs.sh" ]; then
        (cd deploy && ./generate_sensor_certs.sh >/dev/null 2>&1)
    else
        ./generate_sensor_certs.sh >/dev/null 2>&1
    fi

    if [ -f "certs/cert.pem" ]; then
        echo -e "${OK} Generated CA-signed TLS certificates"
    else
        echo -e "${FAIL} CA-signed TLS certificate generation failed"
        exit 1
    fi
else
    echo -e "${OK} TLS certificates present"
fi

CONFIG_PATH="config.toml"
if [ -f "deploy/config.toml" ]; then CONFIG_PATH="deploy/config.toml"; fi

if grep -q 'jwt_secret = "CHANGE_ME_IN_PRODUCTION"' "$CONFIG_PATH" 2>/dev/null; then
    NEW_SECRET=$(openssl rand -hex 32)
    sed -i.tmp "s/jwt_secret = \"CHANGE_ME_IN_PRODUCTION\"/jwt_secret = \"$NEW_SECRET\"/" "$CONFIG_PATH" && rm -f "${CONFIG_PATH}.tmp"
    echo -e "${OK} Generated secure JWT secret"
fi

# Generate admin password on first boot
if grep -q 'default_admin_password = "GENERATE_ON_FIRST_BOOT"' "$CONFIG_PATH" 2>/dev/null; then
    ADMIN_PASS=$(openssl rand -base64 18 | tr -d '/+=' | head -c 16)
    sed -i.tmp "s/default_admin_password = \"GENERATE_ON_FIRST_BOOT\"/default_admin_password = \"$ADMIN_PASS\"/" "$CONFIG_PATH" && rm -f "${CONFIG_PATH}.tmp"
    echo -e "${OK} Generated admin password"
    GENERATED_ADMIN_PASS="$ADMIN_PASS"
fi

# Extract Mode
DEPLOY_MODE=$(grep '^mode' "$CONFIG_PATH" 2>/dev/null | cut -d'"' -f2 || echo "full")
echo -e "${INFO} Active Deployment Profile: ${DEPLOY_MODE^^}"

# 5. eBPF Headers
VMLINUX="ebpf_probes/vmlinux.h"
if [ ! -f "$VMLINUX" ]; then
    if curl -sL --retry 3 "https://raw.githubusercontent.com/aquasecurity/tracee/main/pkg/ebpf/c/vmlinux.h" -o "$VMLINUX" >/dev/null 2>&1; then
        echo -e "${OK} Fetched vmlinux.h"
    else
        echo -e "${FAIL} Failed to fetch vmlinux.h"
        exit 1
    fi
else
    echo -e "${OK} vmlinux.h present"
fi

# 5b. Supply Chain Scan (optional: SCAN_DEPS=1 ./run.sh)
if [ "${SCAN_DEPS:-0}" = "1" ]; then
    SCAN_SCRIPT="deploy/supply_chain_scan.sh"
    [ -f "$SCAN_SCRIPT" ] || SCAN_SCRIPT="supply_chain_scan.sh"
    if [ -f "$SCAN_SCRIPT" ]; then
        chmod +x "$SCAN_SCRIPT"
        CONTAINER_RUNTIME="$RUNTIME" bash "$SCAN_SCRIPT" || true
    else
        echo -e "${INFO} Supply chain scan requested but script not found"
    fi
fi

# 6. Compose Pathing
get_open_port() {
    for port in {8000..9000}; do
        if ! ss -tuln | grep -q ":$port "; then
            echo "$port"
            return
        fi
    done
    echo 8443 # Fallback
}

export DASH_PORT=$(get_open_port)

DEPLOY_MODE=$(echo "$DEPLOY_MODE" | tr -d '\r' | tr '[:upper:]' '[:lower:]')

if [ "$DEPLOY_MODE" != "collector" ]; then
    echo -e "${INFO} Allocated Dashboard Port: $DASH_PORT"
fi

if [ "$DEPLOY_MODE" == "collector" ]; then
    BASE_COMPOSE="docker-compose.collector"
else
    # Both "standard" and "full" use the same two-container stack
    # (core + dashboard). Behavior differs via config.toml only.
    BASE_COMPOSE="docker-compose.standard"
fi

COMPOSE_FILE=""

# Since we are anchored to the root, we know exactly where to look
if [ -f "deploy/${BASE_COMPOSE}.yaml" ]; then
    cd deploy && COMPOSE_FILE="${BASE_COMPOSE}.yaml"
elif [ -f "deploy/${BASE_COMPOSE}.yml" ]; then
    cd deploy && COMPOSE_FILE="${BASE_COMPOSE}.yml"
elif [ -f "${BASE_COMPOSE}.yaml" ]; then
    COMPOSE_FILE="${BASE_COMPOSE}.yaml"
elif [ -f "${BASE_COMPOSE}.yml" ]; then
    COMPOSE_FILE="${BASE_COMPOSE}.yml"
else
    echo -e "${FAIL} Orchestration manifest not found."
    echo -e "${INFO} Searched for: $(pwd)/deploy/${BASE_COMPOSE}.yaml AND $(pwd)/${BASE_COMPOSE}.yaml"
    exit 1
fi

echo -e "${OK} Located orchestration manifest: $COMPOSE_FILE"

# 7. Execution
$COMPOSE_CMD -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
echo -e "${OK} Cleared previous state"

echo -e "\n${INFO} Commencing native build..."
echo -e "------------------------------------------------------------------"

if ! DASHBOARD_PORT=$DASH_PORT $COMPOSE_CMD -f "$COMPOSE_FILE" build; then
    echo -e "------------------------------------------------------------------"
    echo -e "${FAIL} Build process failed. Halting execution."
    exit 1
fi

echo -e "\n${INFO} Commencing orchestration..."
echo -e "------------------------------------------------------------------"

if ! DASHBOARD_PORT=$DASH_PORT $COMPOSE_CMD -f "$COMPOSE_FILE" up -d; then
    echo -e "------------------------------------------------------------------"
    echo -e "${FAIL} Container orchestration failed."
    exit 1
fi

echo -e "------------------------------------------------------------------"
echo -e "${OK} Containers compiled and launched successfully"

$RUNTIME image prune -f --filter "label=org.opencontainers.image.name=c2-sensor*" >/dev/null 2>&1 || true
echo -e "${OK} Cleaned dangling build artifacts\n"

# 8. Report
if [ "$DEPLOY_MODE" != "collector" ]; then
    echo -e "${INFO} Sensor UI          -> https://127.0.0.1:$DASH_PORT"
    if [ -n "${GENERATED_ADMIN_PASS:-}" ]; then
        echo -e ""
        echo -e "${INFO} ┌─────────────────────────────────────────────────┐"
        echo -e "${INFO} │  FIRST BOOT -- Save these credentials now:      │"
        echo -e "${INFO} │  Username: admin                                │"
        echo -e "${INFO} │  Password: $GENERATED_ADMIN_PASS                │"
        echo -e "${INFO} │  This password will NOT be shown again.         │"
        echo -e "${INFO} └─────────────────────────────────────────────────┘"
        echo -e ""
    else
        echo -e "${INFO} Default Admin Auth -> admin : (see config.toml or C2_ADMIN_PASSWORD env)"
    fi
fi

if [[ "$COMPOSE_FILE" == *"docker-compose"* ]] && [ "$(basename $(pwd))" == "deploy" ]; then
    echo -e "${INFO} Live Core Logs     -> cd deploy && $COMPOSE_CMD logs -f c2-sensor-core"
else
    echo -e "${INFO} Live Core Logs     -> $COMPOSE_CMD -f $COMPOSE_FILE logs -f c2-sensor-core"
fi
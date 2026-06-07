#!/usr/bin/env bash
# =================================================================================
# File:        run_with_dashboard.sh
# Component:   Linux Sentinel -- Forensic Workbench Orchestrator
# Description: Deploys the complete Linux Sentinel suite (Agent + UI) via Compose.
# Role:        Validates dependencies, provisions local Certificate Authority (CA)
#              material for the UI, injects secure JWT secrets into the dashboard,
#              stages threat intelligence, and synchronizes the multi-container
#              deployment using Podman/Docker Compose.
# =================================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: Linux Sentinel requires root for eBPF kernel access."
    echo "Re-run with: sudo $0"
    exit 1
fi

trap 'echo "[!] FATAL: Deployment failed on line $LINENO. Review diagnostics above." >&2' ERR

echo "=================================================================="
echo "        LINUX SENTINEL | FORENSIC WORKBENCH ORCHESTRATOR          "
echo "=================================================================="

# ==============================================================================
# 1. Pre-Flight Dependency Validation
# ==============================================================================
echo "[*] Phase 1: Validating System Dependencies..."

check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "[-] FATAL: Required dependency '$1' is not installed."
        exit 1
    fi
}

check_dependency "openssl"
check_dependency "curl"
check_dependency "unzip"
check_dependency "sed"

CONTAINER_CLI="docker"
COMPOSE_CLI="docker-compose"
if command -v podman &> /dev/null; then
    CONTAINER_CLI="podman"
    if command -v podman-compose &> /dev/null; then
        COMPOSE_CLI="podman-compose"
    elif podman compose version &> /dev/null; then
        COMPOSE_CLI="podman compose"
    else
        echo "FATAL: podman detected but neither podman-compose nor 'podman compose' is available."
        exit 1
    fi
fi
echo "[+] Orchestration Engine: $COMPOSE_CLI"

# ==============================================================================
# 2. Configuration & State Validation
# ==============================================================================
echo "[*] Phase 2: Verifying Configuration Anchors..."

if [ ! -f "master.toml" ]; then
    echo "[-] FATAL: master.toml not found in the current directory."
    exit 1
fi

if [ ! -f "dashboard_config.yaml" ]; then
    echo "[-] FATAL: dashboard_config.yaml not found. Required for the Workbench."
    exit 1
fi

if [ ! -f "dashboard/generate_dashboard_certs.sh" ]; then
    echo "[-] FATAL: dashboard/generate_dashboard_certs.sh not found. Ensure dashboard files are in the dashboard/ directory."
    exit 1
fi

chmod +x dashboard/generate_dashboard_certs.sh

CERTS_DIR="$(pwd)/certs"
DASHBOARD_CERTS_DIR="$(pwd)/dashboard/certs"
mkdir -p "$CERTS_DIR"
mkdir -p "$DASHBOARD_CERTS_DIR"
mkdir -p ./dashboard/data
chown 10001:10001 ./dashboard/data

# ==============================================================================
# 3. Cryptographic Bootstrapping
# ==============================================================================
echo "[*] Phase 3: Provisioning Cryptographic Material..."

TOKEN_FILE="$CERTS_DIR/auth_token.txt"
if [ -z "${SENTINEL_AUTH_TOKEN:-}" ]; then
    if [ -f "$TOKEN_FILE" ]; then
        echo "    [*] Loading existing master authentication token from cache..."
        export SENTINEL_AUTH_TOKEN=$(cat "$TOKEN_FILE")
    else
        echo "    [*] Generating new 256-bit secure master authentication token..."
        export SENTINEL_AUTH_TOKEN=$(openssl rand -hex 32)
        echo "$SENTINEL_AUTH_TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
    fi
fi

if grep -q "CHANGE_THIS_SUPER_SECRET_KEY_FOR_PRODUCTION" dashboard_config.yaml; then
    echo "    [*] Default JWT secret detected in configuration. Generating secure key..."
    NEW_JWT_SECRET=$(openssl rand -hex 48)
    sed -i.bak "s/CHANGE_THIS_SUPER_SECRET_KEY_FOR_PRODUCTION/$NEW_JWT_SECRET/g" dashboard_config.yaml
    rm -f dashboard_config.yaml.bak
    echo "    [+] Secure JWT secret successfully injected into dashboard_config.yaml."
fi

# ==============================================================================
# 4. Local Certificate Authority (CA) & TLS Provisioning
# ==============================================================================
echo "[*] Phase 4: Initializing Transport Layer Security (TLS)..."

TLS_CERT="$CERTS_DIR/tls.crt"
TLS_KEY="$CERTS_DIR/tls.key"

if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
    echo "    [*] Generating TLS certificates for the Agent Core API..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$TLS_KEY" -out "$TLS_CERT" \
        -sha256 -days 3650 -nodes \
        -subj "/C=US/ST=Cyber/L=Grid/O=Sentinel/CN=localhost" \
        2>/dev/null
    chmod 600 "$TLS_KEY"
else
    echo "    [+] Agent Core TLS certificates present."
fi

DASH_TLS_CERT="$DASHBOARD_CERTS_DIR/dashboard_cert.pem"
DASH_TLS_KEY="$DASHBOARD_CERTS_DIR/dashboard_key.pem"

if [ ! -f "$DASH_TLS_CERT" ] || [ ! -f "$DASH_TLS_KEY" ]; then
    echo "    [*] Delegating Forensic Dashboard TLS to Local CA Infrastructure..."
    bash ./dashboard/generate_dashboard_certs.sh

    if [ ! -f "$DASH_TLS_CERT" ] || [ ! -f "$DASH_TLS_KEY" ]; then
        echo "[-] FATAL: generate_dashboard_certs.sh failed."
        exit 1
    fi
    echo "    [+] Dashboard CA chain staged successfully."
else
    echo "    [+] Forensic Dashboard TLS certificates present."
fi

chown 10001:10001 "$DASH_TLS_KEY" "$DASH_TLS_CERT"
chmod 600 "$DASH_TLS_KEY"
chmod 644 "$DASH_TLS_CERT"

# ==============================================================================
# 5. Threat Intelligence Integration (Unified Staging)
# ==============================================================================
echo "[*] Phase 5: Staging Global Threat Intelligence..."
mkdir -p ./intel_staging/yara ./intel_staging/sigma/rules ./intel_staging/bpf ./intel_staging/lists
touch ./intel_staging/lists/malicious-ips.txt

fetch_intel() {
    local url="$1"
    local dest="$2"
    if ! curl -sL --retry 3 --retry-delay 2 "$url" -o "$dest"; then
        echo "[-] FATAL: Failed to fetch threat intelligence from $url"
        exit 1
    fi
}

echo "    [*] Fetching Multi-Source YARA Intelligence..."
YARA_SOURCES=(
    "ElasticLabs|https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip|protections-artifacts-main/yara"
    "ReversingLabs|https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip|reversinglabs-yara-rules-develop/yara"
    "SignatureBase|https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip|signature-base-master/yara"
)

for source in "${YARA_SOURCES[@]}"; do
    IFS="|" read -r NAME URL SUBPATH <<< "$source"
    echo "        [*] Downloading $NAME..."
    fetch_intel "$URL" "./intel_staging/${NAME}.zip"
    unzip -q "./intel_staging/${NAME}.zip" -d "./intel_staging/${NAME}_tmp"
    mv "./intel_staging/${NAME}_tmp/${SUBPATH}/"* ./intel_staging/yara/ 2>/dev/null || true
    rm -rf "./intel_staging/${NAME}_tmp" "./intel_staging/${NAME}.zip"
done

echo "    [*] Sanitizing YARA payload: Removing proprietary Nextron/Thor signatures..."
grep -rl "is__" ./intel_staging/yara/ | xargs rm -f 2>/dev/null || true

echo "    [*] Sanitizing YARA payload: Removing unsupported dynamic sandbox modules..."
grep -rlE 'import "(cuckoo|magic|hash)"' ./intel_staging/yara/ | xargs rm -f 2>/dev/null || true

echo "    [*] Sanitizing YARA payload: Stripping relative include paths..."
find ./intel_staging/yara/ -type f -name "*.yar*" -exec sed -i '/^[[:space:]]*include "/d' {} +

echo "    [*] Fetching baseline Sigma rules..."
fetch_intel "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" "./intel_staging/sigma_base.zip"
unzip -q ./intel_staging/sigma_base.zip -d ./intel_staging/sigma_tmp
mv ./intel_staging/sigma_tmp/sigma-master/rules/linux/ ./intel_staging/sigma/rules/ 2>/dev/null || true
rm -rf ./intel_staging/sigma_tmp ./intel_staging/sigma_base.zip

echo "    [*] Fetching Cybereason owLSM (eBPF-optimized) Sigma rules..."
fetch_intel "https://github.com/Cybereason-Public/owLSM/archive/refs/heads/main.zip" "./intel_staging/sigma_owlsm.zip"
unzip -q ./intel_staging/sigma_owlsm.zip -d ./intel_staging/sigma_owlsm_tmp
find ./intel_staging/sigma_owlsm_tmp/ -name "*.yml" -exec cp {} ./intel_staging/sigma/rules/ \; 2>/dev/null || true
rm -rf ./intel_staging/sigma_owlsm_tmp ./intel_staging/sigma_owlsm.zip

echo "    [*] Fetching generic Tracee vmlinux.h for eBPF offline compilation..."
fetch_intel "https://raw.githubusercontent.com/aquasecurity/tracee/main/pkg/ebpf/c/vmlinux.h" "./intel_staging/bpf/vmlinux.h"

chmod -R 744 ./intel_staging/yara/
chmod -R 744 ./intel_staging/bpf/
chmod -R 744 ./intel_staging/lists/

echo "Staging ClamAV definitions on host..."
mkdir -p ./sentinel-data/clamav
curl -sL https://database.clamav.net/main.cvd -o ./sentinel-data/clamav/main.cvd
curl -sL https://database.clamav.net/daily.cvd -o ./sentinel-data/clamav/daily.cvd
curl -sL https://database.clamav.net/bytecode.cvd -o ./sentinel-data/clamav/bytecode.cvd

# ==============================================================================
# 6. Container Orchestration & Execution
# ==============================================================================
echo "[*] Phase 6: Executing Container Build & Orchestration..."

mkdir -p ./sentinel-data/diagnostics
mkdir -p ./sentinel-data/parquet
chown -R root:root ./sentinel-data
chmod -R 750 ./sentinel-data
chmod 770 ./sentinel-data/clamav

export SENTINEL_AUTH_TOKEN

echo "    [*] Silently cleaning up previous orchestration state..."
$COMPOSE_CLI down --remove-orphans >/dev/null 2>&1 || true
$CONTAINER_CLI rm -f linux-sentinel-agent >/dev/null 2>&1 || true

if ! $COMPOSE_CLI up --build -d; then
    echo "[-] FATAL: Container orchestration failed. Review the build output above."
    exit 1
fi

echo "    [*] Cleaning up dangling build artifacts..."
$CONTAINER_CLI system prune -f >/dev/null 2>&1

echo "=================================================================="
echo "[+] DEPLOYMENT SUCCESSFUL"
echo "    Agent API Listener:         https://127.0.0.1:8080"
echo "    Forensic Workbench Uplink:  https://127.0.0.1:8443"
echo ""
echo "    Core Auth Token:            $SENTINEL_AUTH_TOKEN"
echo "    Default Workbench Login:    admin / admin"
echo "=================================================================="
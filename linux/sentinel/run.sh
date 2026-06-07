#!/usr/bin/env bash
# ====================================================================================
# File:        run.sh
# Component:   Linux Sentinel -- Standalone Agent Deployment
# Description: Bootstraps and deploys the Linux Sentinel agent as a single container.
# Role:        Automates pre-flight cryptographic generation (TLS, Auth Token),
#              stages global threat intelligence (YARA, Sigma, Tracee vmlinux.h),
#              builds the container image, and launches the agent with the precise
#              set of kernel capabilities required for eBPF operations.
# ====================================================================================

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: Linux Sentinel requires root for eBPF kernel access."
    echo "Re-run with: sudo $0"
    exit 1
fi

CONTAINER_CLI="docker"
if command -v podman &> /dev/null; then
    CONTAINER_CLI="podman"
fi

# 1. Pre-Flight Validation & Configuration
if [ ! -f "master.toml" ]; then
    echo "FATAL: master.toml not found in current directory."
    exit 1
fi

CERTS_DIR="$(pwd)/certs"
mkdir -p "$CERTS_DIR"

# 2. Automated Prerequisite Generation (Auth Token & TLS)
TOKEN_FILE="$CERTS_DIR/auth_token.txt"
if [ -z "${SENTINEL_AUTH_TOKEN:-}" ]; then
    if [ -f "$TOKEN_FILE" ]; then
        echo "Loading existing auth token from $TOKEN_FILE..."
        export SENTINEL_AUTH_TOKEN=$(cat "$TOKEN_FILE")
    else
        echo "Generating new cryptographically secure auth token..."
        export SENTINEL_AUTH_TOKEN=$(openssl rand -hex 32)
        echo "$SENTINEL_AUTH_TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
    fi
fi

echo "=================================================================="
echo "SENTINEL AUTH TOKEN: $SENTINEL_AUTH_TOKEN"
echo "Store this token securely. It is required for API and SIEM access."
echo "A copy has been saved to ./certs/auth_token.txt"
echo "=================================================================="

TLS_CERT="$CERTS_DIR/tls.crt"
TLS_KEY="$CERTS_DIR/tls.key"

if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
    echo "Generating 4096-bit RSA TLS certificates..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$TLS_KEY" -out "$TLS_CERT" \
        -sha256 -days 3650 -nodes \
        -subj "/C=US/ST=Cyber/L=Grid/O=Sentinel/CN=localhost" \
        2>/dev/null
    chmod 600 "$TLS_KEY"
else
    echo "TLS certificates found. Skipping generation."
fi

# 3. Threat Intelligence Integration (Unified Staging)
echo "Staging Global Threat Intelligence..."
mkdir -p ./intel_staging/yara ./intel_staging/sigma/rules ./intel_staging/bpf ./intel_staging/lists
touch ./intel_staging/lists/malicious-ips.txt

echo "Fetching Multi-Source YARA Intelligence..."
YARA_SOURCES=(
    "ElasticLabs|https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip|protections-artifacts-main/yara"
    "ReversingLabs|https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip|reversinglabs-yara-rules-develop/yara"
    "SignatureBase|https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip|signature-base-master/yara"
)

for source in "${YARA_SOURCES[@]}"; do
    IFS="|" read -r NAME URL SUBPATH <<< "$source"
    echo "    [*] Downloading $NAME..."
    curl -sL "$URL" -o "./intel_staging/${NAME}.zip"
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

echo "Fetching baseline Sigma rules..."
curl -sL "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" -o ./intel_staging/sigma_base.zip
unzip -q ./intel_staging/sigma_base.zip -d ./intel_staging/sigma_tmp
mv ./intel_staging/sigma_tmp/sigma-master/rules/linux/ ./intel_staging/sigma/rules/ 2>/dev/null || true
rm -rf ./intel_staging/sigma_tmp ./intel_staging/sigma_base.zip

echo "Fetching Cybereason owLSM (eBPF-optimized) Sigma rules..."
curl -sL "https://github.com/Cybereason-Public/owLSM/archive/refs/heads/main.zip" -o ./intel_staging/sigma_owlsm.zip
unzip -q ./intel_staging/sigma_owlsm.zip -d ./intel_staging/sigma_owlsm_tmp
find ./intel_staging/sigma_owlsm_tmp/ -name "*.yml" -exec cp {} ./intel_staging/sigma/rules/ \; 2>/dev/null || true
rm -rf ./intel_staging/sigma_owlsm_tmp ./intel_staging/sigma_owlsm.zip

echo "Fetching generic Tracee vmlinux.h for eBPF build fallback..."
curl -sL "https://raw.githubusercontent.com/aquasecurity/tracee/main/pkg/ebpf/c/vmlinux.h" -o ./intel_staging/bpf/vmlinux.h

chmod -R 744 ./intel_staging/yara/
chmod -R 744 ./intel_staging/bpf/
chmod -R 744 ./intel_staging/lists/

echo "Staging ClamAV definitions on host..."
mkdir -p ./sentinel-data/clamav
curl -sL https://database.clamav.net/main.cvd -o ./sentinel-data/clamav/main.cvd
curl -sL https://database.clamav.net/daily.cvd -o ./sentinel-data/clamav/daily.cvd
curl -sL https://database.clamav.net/bytecode.cvd -o ./sentinel-data/clamav/bytecode.cvd

# 4. Build and Deploy
echo "Building Linux Sentinel v0.3.0 (Alpha) using $CONTAINER_CLI..."
$CONTAINER_CLI build -t linux-sentinel:latest .

echo "Deploying sensor..."
$CONTAINER_CLI rm -f linux-sentinel-agent >/dev/null 2>&1 || true

mkdir -p ./sentinel-data/diagnostics
mkdir -p ./sentinel-data/parquet
chown -R root:root ./sentinel-data
chmod -R 750 ./sentinel-data
chmod 770 ./sentinel-data/clamav

$CONTAINER_CLI run -d \
    --name linux-sentinel-agent \
    --cap-drop ALL \
    --cap-add NET_ADMIN \
    --cap-add NET_BIND_SERVICE \
    --cap-add DAC_READ_SEARCH \
    --cap-add SYS_PTRACE \
    --cap-add SYS_ADMIN \
    --cap-add SYS_RESOURCE \
    --cap-add BPF \
    --cap-add PERFMON \
    --cap-add KILL \
    -e SENTINEL_AUTH_TOKEN="${SENTINEL_AUTH_TOKEN}" \
    -p 127.0.0.1:8080:8080 \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    -v /sys/fs/bpf:/sys/fs/bpf:rw \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    -v /proc:/host/proc:ro \
    -v sentinel-data:/var/log/linux-sentinel:z \
    -v sentinel-clamav:/var/lib/clamav:z \
    -v sentinel-parquet:/var/backups/linux-sentinel/parquet:z \
    -v $(pwd)/certs:/opt/linux-sentinel/certs:ro,z \
    -v $(pwd)/master.toml:/opt/linux-sentinel/master.toml:ro,z \
    -v $(pwd)/intel_staging:/opt/linux-sentinel/intel_staging:ro,z \
    linux-sentinel:latest

echo "=================================================================="
echo "Deployment Complete. Linux Sentinel API is listening on https://127.0.0.1:8080"
echo "Use the provided auth token to securely connect."
echo "=================================================================="
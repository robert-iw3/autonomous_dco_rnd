#!/usr/bin/env bash
# =================================================================================
# File:        build_offline_bundle.sh
# Component:   Linux Sentinel -- Airgap Packager
# Description: Compiles the sensor and UI, downloads threat intelligence, and
#              exports images into a self-contained offline transport bundle.
#              Supports both Docker and Podman environments dynamically.
# =================================================================================

set -euo pipefail

BUNDLE_DIR="linux_sentinel_offline_bundle"
IMAGES_DIR="$BUNDLE_DIR/images"
INTEL_DIR="$BUNDLE_DIR/intel_staging"

echo "=================================================================="
echo "    LINUX SENTINEL | AIRGAP BUNDLE GENERATOR"
echo "=================================================================="

# Detect Container Engine
CONTAINER_CLI="docker"
if command -v podman &> /dev/null; then
    CONTAINER_CLI="podman"
    echo "[*] Podman detected for local build operations."
else
    echo "[*] Docker detected for local build operations."
fi

# 1. Prepare Directory Structure
rm -rf "$BUNDLE_DIR"
mkdir -p "$IMAGES_DIR" "$INTEL_DIR/yara" "$INTEL_DIR/sigma/rules" "$INTEL_DIR/bpf" "$INTEL_DIR/lists"
touch "$INTEL_DIR/lists/malicious-ips.txt"

# ==============================================================================
# 2. Stage Threat Intelligence
# ==============================================================================
echo "[*] Fetching Global Threat Intelligence..."

echo "    [*] Fetching Multi-Source YARA Intelligence..."
YARA_SOURCES=(
    "ElasticLabs|https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip|protections-artifacts-main/yara"
    "ReversingLabs|https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip|reversinglabs-yara-rules-develop/yara"
    "SignatureBase|https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip|signature-base-master/yara"
)

for source in "${YARA_SOURCES[@]}"; do
    IFS="|" read -r NAME URL SUBPATH <<< "$source"
    echo "        [*] Downloading $NAME..."
    curl -sL "$URL" -o "$INTEL_DIR/${NAME}.zip"
    unzip -q "$INTEL_DIR/${NAME}.zip" -d "$INTEL_DIR/${NAME}_tmp"
    mv "$INTEL_DIR/${NAME}_tmp/${SUBPATH}/"* "$INTEL_DIR/yara/" 2>/dev/null || true
    rm -rf "$INTEL_DIR/${NAME}_tmp" "$INTEL_DIR/${NAME}.zip"
done

echo "    [*] Sanitizing YARA payload..."
grep -rl "is__" "$INTEL_DIR/yara/" | xargs rm -f 2>/dev/null || true
grep -rlE 'import "(cuckoo|magic|hash)"' "$INTEL_DIR/yara/" | xargs rm -f 2>/dev/null || true
find "$INTEL_DIR/yara/" -type f -name "*.yar*" -exec sed -i '/^[[:space:]]*include "/d' {} +

echo "    [*] Fetching baseline SigmaHQ rules..."
curl -sL "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" -o "$INTEL_DIR/sigma_base.zip"
unzip -q "$INTEL_DIR/sigma_base.zip" -d "$INTEL_DIR/sigma_tmp"
mv "$INTEL_DIR/sigma_tmp/sigma-master/rules/linux/" "$INTEL_DIR/sigma/rules/" 2>/dev/null || true
rm -rf "$INTEL_DIR/sigma_tmp" "$INTEL_DIR/sigma_base.zip"

echo "    [*] Fetching Cybereason owLSM (eBPF-optimized) Sigma rules..."
curl -sL "https://github.com/Cybereason-Public/owLSM/archive/refs/heads/main.zip" -o "$INTEL_DIR/sigma_owlsm.zip"
unzip -q "$INTEL_DIR/sigma_owlsm.zip" -d "$INTEL_DIR/sigma_owlsm_tmp"
find "$INTEL_DIR/sigma_owlsm_tmp/" -name "*.yml" -exec cp {} "$INTEL_DIR/sigma/rules/" \; 2>/dev/null || true
rm -rf "$INTEL_DIR/sigma_owlsm_tmp" "$INTEL_DIR/sigma_owlsm.zip"

curl -sL "https://raw.githubusercontent.com/aquasecurity/tracee/main/pkg/ebpf/c/vmlinux.h" -o "$INTEL_DIR/bpf/vmlinux.h"

chmod -R 744 "$INTEL_DIR/"

# ==============================================================================
# 3. Build & Export Container Images
# ==============================================================================
echo "[*] Building local container images using $CONTAINER_CLI..."
$CONTAINER_CLI build -t linux-sentinel:latest .
$CONTAINER_CLI build -t linux-sentinel-dashboard:latest ./dashboard

echo "[*] Exporting images to tarballs (this may take a minute)..."
$CONTAINER_CLI save linux-sentinel:latest -o "$IMAGES_DIR/linux-sentinel.tar"
$CONTAINER_CLI save linux-sentinel-dashboard:latest -o "$IMAGES_DIR/linux-sentinel-dashboard.tar"

# ==============================================================================
# 4. Stage Configuration & Scripts
# ==============================================================================
echo "[*] Staging Configuration Artifacts..."
cp master.toml "$BUNDLE_DIR/"
cp dashboard_config.yaml "$BUNDLE_DIR/"

mkdir -p "$BUNDLE_DIR/dashboard"
cp dashboard/generate_dashboard_certs.sh "$BUNDLE_DIR/dashboard/"
chmod +x "$BUNDLE_DIR/dashboard/generate_dashboard_certs.sh"

grep -v "pull_policy: build" docker-compose.yaml | sed '/^ *build:/,+2d' > "$BUNDLE_DIR/docker-compose.yaml"

# ==============================================================================
# 5. Generate Airgap Deployment Script
# ==============================================================================
cat << 'EOF' > "$BUNDLE_DIR/deploy_airgapped.sh"
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: Deployment requires root for eBPF and container networking orchestration."
    exit 1
fi

echo "=================================================================="
echo "    LINUX SENTINEL | SECURE AIRGAP DEPLOYMENT"
echo "=================================================================="

# Detect Target Container Engine
TARGET_CLI="docker"
COMPOSE_CLI="docker-compose"
if command -v podman &> /dev/null; then
    TARGET_CLI="podman"
    COMPOSE_CLI="podman-compose"
fi
echo "[*] Target Environment Engine: $TARGET_CLI"

# 1. Load Pre-packaged Images
echo "[*] Loading container images from tarballs..."
$TARGET_CLI load -i images/linux-sentinel.tar
$TARGET_CLI load -i images/linux-sentinel-dashboard.tar

# 2. Cryptographic Bootstrapping
echo "[*] Provisioning Cryptographic Material..."
mkdir -p certs dashboard/certs dashboard/data
chown 10001:10001 dashboard/data

if [ ! -f "certs/auth_token.txt" ]; then
    export SENTINEL_AUTH_TOKEN=$(openssl rand -hex 32)
    echo "$SENTINEL_AUTH_TOKEN" > certs/auth_token.txt
    chmod 600 certs/auth_token.txt
else
    export SENTINEL_AUTH_TOKEN=$(cat certs/auth_token.txt)
fi

# Agent API TLS
if [ ! -f "certs/tls.crt" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout certs/tls.key -out certs/tls.crt \
        -sha256 -days 3650 -nodes -subj "/C=US/ST=Cyber/L=Grid/O=Sentinel/CN=localhost" 2>/dev/null
    chmod 600 certs/tls.key
fi

# Dashboard TLS
if [ ! -f "dashboard/certs/dashboard_cert.pem" ]; then
    bash ./dashboard/generate_dashboard_certs.sh
    chown 10001:10001 dashboard/certs/dashboard_key.pem dashboard/certs/dashboard_cert.pem
    chmod 600 dashboard/certs/dashboard_key.pem
    chmod 644 dashboard/certs/dashboard_cert.pem
fi

# 3. Secure JWT Injection
if grep -q "CHANGE_THIS_SUPER_SECRET_KEY_FOR_PRODUCTION" dashboard_config.yaml; then
    NEW_JWT_SECRET=$(openssl rand -hex 48)
    sed -i.bak "s/CHANGE_THIS_SUPER_SECRET_KEY_FOR_PRODUCTION/$NEW_JWT_SECRET/g" dashboard_config.yaml
    rm -f dashboard_config.yaml.bak
fi

# 4. Orchestration
echo "[*] Executing Container Orchestration via $COMPOSE_CLI..."
$COMPOSE_CLI down --remove-orphans >/dev/null 2>&1 || true
$COMPOSE_CLI up -d --no-build

echo "[+] AIRGAP DEPLOYMENT SUCCESSFUL"
echo "    Core Auth Token: $SENTINEL_AUTH_TOKEN"
EOF

chmod +x "$BUNDLE_DIR/deploy_airgapped.sh"

# ==============================================================================
# 6. Finalization
# ==============================================================================
echo "[*] Compressing bundle..."
tar -czf linux_sentinel_offline_bundle.tar.gz "$BUNDLE_DIR"
rm -rf "$BUNDLE_DIR"

echo "=================================================================="
echo "[+] BUNDLE COMPLETE: linux_sentinel_offline_bundle.tar.gz"
echo "=================================================================="
#!/bin/bash
# ==============================================================================
# Sentinel Nexus -- Single-Shot Deployment Entrypoint
#
# Usage:
#   ./deploy.sh [environment-file] [--skip-mlops] [--offline]
#
# Examples:
#   ./deploy.sh                                              # online, defaults to production
#   ./deploy.sh orchestration/environments/dev.yaml
#   ./deploy.sh orchestration/environments/production.yaml --skip-mlops
#   ./deploy.sh --offline                                    # fully air-gapped deployment
#   ./deploy.sh orchestration/environments/production.yaml --offline --skip-mlops
#
# Offline mode prerequisites (run deployment_prep/ phases first):
#   cd deployment_prep && make deploy-offline
#   OR manually: make verify && make load && make install-deps, then ./deploy.sh --offline
#
# Offline mode skips: Terraform provisioning (hosts must already exist),
#   all pip/ansible-galaxy internet calls (uses pre-downloaded wheels/collections).
#   All docker/podman pulls are suppressed -- images loaded from bundle tarballs.
#
# Required environment variables (CI secrets / .env):
#   ANSIBLE_VAULT_PASSWORD   -- decrypts infrastructure/ansible/group_vars/all/vault.yml
#   SSH_PRIVATE_KEY          -- private key Ansible uses to reach provisioned VMs
#
# For VMware targets, also required:
#   VSPHERE_USER, VSPHERE_PASSWORD, VSPHERE_SERVER
#
# For AWS targets:
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY  (or IAM role on the runner)
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# -- Argument parsing -----------------------------------------------------------
ENV_FILE="${1:-orchestration/environments/production.yaml}"
SKIP_MLOPS=false
OFFLINE_MODE=false
FORCE_BARE_METAL=false
FORCE_CONTAINER=false
for arg in "$@"; do
    [[ "$arg" == "--skip-mlops"       ]] && SKIP_MLOPS=true
    [[ "$arg" == "--offline"          ]] && OFFLINE_MODE=true
    [[ "$arg" == "--force-bare-metal" ]] && FORCE_BARE_METAL=true
    [[ "$arg" == "--force-container"  ]] && FORCE_CONTAINER=true
done
# Allow env var override
[[ "${NEXUS_OFFLINE_MODE:-false}" == "true" ]] && OFFLINE_MODE=true
export NEXUS_OFFLINE_MODE="$OFFLINE_MODE"

# -- Deployment tier detection --------------------------------------------------
# Reads endpoint_count from the environment YAML and sets BARE_METAL_ENABLED.
# Threshold: > 20,000 endpoints → bare-metal path for I/O-critical nodes.
#
# Override flags:
#   --force-bare-metal  always use bare-metal path (testing on any fleet size)
#   --force-container   always use containerised path (CI/dev)
BARE_METAL_THRESHOLD=20000
BARE_METAL_ENABLED=false

detect_deployment_tier() {
    local endpoint_count=0
    endpoint_count=$(python3 -c "
import yaml, sys
try:
    cfg = yaml.safe_load(open('$ENV_FILE'))
    print(cfg.get('endpoint_count', 0))
except Exception as e:
    print(0)
" 2>/dev/null || echo 0)

    DEPLOYMENT_TIER=$(python3 -c "
import yaml, sys
try:
    cfg = yaml.safe_load(open('$ENV_FILE'))
    print(cfg.get('deployment_tier', 'small'))
except:
    print('small')
" 2>/dev/null || echo "small")

    if [[ "$FORCE_BARE_METAL" == "true" ]]; then
        BARE_METAL_ENABLED=true
        DEPLOYMENT_TIER="large"
        log_warn "Forced bare-metal mode (--force-bare-metal)"
    elif [[ "$FORCE_CONTAINER" == "true" ]]; then
        BARE_METAL_ENABLED=false
        DEPLOYMENT_TIER="small"
        log_warn "Forced containerised mode (--force-container)"
    elif [[ "$endpoint_count" -gt "$BARE_METAL_THRESHOLD" ]]; then
        BARE_METAL_ENABLED=true
    else
        BARE_METAL_ENABLED=false
    fi

    export BARE_METAL_ENABLED DEPLOYMENT_TIER
}
detect_deployment_tier

# -- Color helpers -------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info()  { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[!] ERROR:${NC} $*" >&2; }

# -- Prerequisite checks --------------------------------------------------------
check_prereqs() {
    log_info "Checking prerequisites..."
    local missing=()
    local required_cmds=(ansible-playbook ansible python3 pip3)
    # Terraform only required in online mode (provisioning); skip in air-gap deployments
    [[ "$OFFLINE_MODE" == "false" ]] && required_cmds+=(terraform)
    for cmd in "${required_cmds[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    python3 -c "import yaml, jinja2" 2>/dev/null || missing+=("python3-yaml/jinja2")
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing prerequisites: ${missing[*]}"
        [[ "$OFFLINE_MODE" == "true" ]] && \
            log_error "  Offline mode: install from deployment_prep/wheels/ using pip --no-index"
        exit 1
    fi
    log_ok "All prerequisites satisfied."
}

# -- Offline: install Python/Ansible deps from pre-downloaded bundle -----------
install_offline_deps() {
    local prep_dir="${REPO_ROOT}/deployment_prep"
    if [[ ! -d "${prep_dir}/wheels" ]]; then
        log_warn "deployment_prep/wheels/ not found -- skipping offline pip install."
        return 0
    fi
    log_info "  Installing Python deps from offline wheel cache..."
    pip3 install --no-index --find-links "${prep_dir}/wheels/" \
        -r "${prep_dir}/python_requirements.txt" -q 2>&1 | tail -2 || true

    if [[ -d "${prep_dir}/collections" ]]; then
        log_info "  Installing Ansible collections from offline cache..."
        ansible-galaxy collection install --offline \
            -r "${prep_dir}/ansible_requirements.yml" \
            -p "${prep_dir}/collections/" 2>/dev/null || true
    fi
    log_ok "Offline dependencies installed."
}

# -- Ansible extra vars: propagate offline flag into every role ----------------
ansible_offline_vars() {
    [[ "$OFFLINE_MODE" == "true" ]] && echo "-e nexus_offline=true -e nexus_skip_pull=true" || echo ""
}

# Propagate bare-metal tier to every Ansible run
ansible_tier_vars() {
    echo "-e bare_metal_enabled=${BARE_METAL_ENABLED} -e deployment_tier=${DEPLOYMENT_TIER} -e endpoint_count=$(python3 -c "import yaml; print(yaml.safe_load(open('$ENV_FILE')).get('endpoint_count',0))" 2>/dev/null || echo 0)"
}

# -- Vault password setup -------------------------------------------------------
VAULT_PASS_FILE=""
setup_vault() {
    if [[ -n "${ANSIBLE_VAULT_PASSWORD:-}" ]]; then
        VAULT_PASS_FILE="$(mktemp)"
        chmod 600 "$VAULT_PASS_FILE"
        echo "$ANSIBLE_VAULT_PASSWORD" > "$VAULT_PASS_FILE"
        trap 'rm -f "$VAULT_PASS_FILE"' EXIT
        log_ok "Vault password loaded from environment variable."
    elif [[ -f ".vault_pass" ]]; then
        VAULT_PASS_FILE=".vault_pass"
        log_ok "Vault password loaded from .vault_pass file."
    else
        log_warn "ANSIBLE_VAULT_PASSWORD not set and .vault_pass not found."
        log_warn "Ansible will prompt for the vault password interactively."
    fi
}
export VAULT_PASS_FILE

vault_args() {
    [[ -n "$VAULT_PASS_FILE" ]] && echo "--vault-password-file $VAULT_PASS_FILE" || echo ""
}

# -- SSH key setup --------------------------------------------------------------
setup_ssh_key() {
    if [[ -n "${SSH_PRIVATE_KEY:-}" ]]; then
        mkdir -p ~/.ssh && chmod 700 ~/.ssh
        echo "$SSH_PRIVATE_KEY" > ~/.ssh/nexus_deploy_key
        chmod 600 ~/.ssh/nexus_deploy_key
        eval "$(ssh-agent -s)" > /dev/null
        ssh-add ~/.ssh/nexus_deploy_key
        log_ok "SSH deploy key installed and added to agent."
    elif [[ -f ~/.ssh/id_rsa ]]; then
        log_warn "SSH_PRIVATE_KEY not set; using ~/.ssh/id_rsa."
    else
        log_warn "No SSH key found. Ansible connections may fail."
    fi
}

# -- Health gate: SSH reachability across all groups ----------------------------
wait_for_ssh() {
    local inventory="$1"
    log_info "Waiting for SSH connectivity on all provisioned hosts (timeout: 10 min)..."
    local deadline=$(( $(date +%s) + 600 ))
    until ansible all -i "$inventory" -m ping --one-line $(vault_args) &>/dev/null; do
        if [[ $(date +%s) -gt $deadline ]]; then
            log_error "SSH health gate timed out after 10 minutes."
            exit 1
        fi
        log_warn "  Hosts not yet reachable -- retrying in 15s..."
        sleep 15
    done
    log_ok "All hosts reachable via SSH."
}

# -- Health gate: NATS JetStream ------------------------------------------------
wait_for_nats() {
    local inventory="$1"
    log_info "Waiting for NATS JetStream readiness..."
    local deadline=$(( $(date +%s) + 300 ))
    until ansible nats -i "$inventory" -m shell \
        -a "nats-server --version && curl -sf http://localhost:8222/healthz" \
        --one-line $(vault_args) &>/dev/null; do
        if [[ $(date +%s) -gt $deadline ]]; then
            log_error "NATS health gate timed out."
            exit 1
        fi
        sleep 10
    done
    log_ok "NATS JetStream healthy."
}

# -- Health gate: Qdrant vector DB ---------------------------------------------
wait_for_qdrant() {
    local inventory="$1"
    log_info "Waiting for Qdrant readiness..."
    local deadline=$(( $(date +%s) + 300 ))
    until ansible qdrant -i "$inventory" -m uri \
        -a "url=http://localhost:6333/healthz method=GET status_code=200" \
        --one-line $(vault_args) &>/dev/null; do
        if [[ $(date +%s) -gt $deadline ]]; then
            log_error "Qdrant health gate timed out."
            exit 1
        fi
        sleep 10
    done
    log_ok "Qdrant healthy."
}

# -- Health gate: Middleware ingress --------------------------------------------
wait_for_middleware() {
    local inventory="$1"
    local port
    port=$(python3 -c "import yaml; c=yaml.safe_load(open('$ENV_FILE')); print(c.get('middleware_ingress_port','8443'))")
    local tls
    tls=$(python3 -c "import yaml; c=yaml.safe_load(open('$ENV_FILE')); print(c.get('middleware_tls_enabled', True))")
    local scheme="https"
    [[ "$tls" == "False" || "$tls" == "false" ]] && scheme="http"

    log_info "Waiting for middleware ingress on :${port}..."
    local deadline=$(( $(date +%s) + 300 ))
    until ansible middleware -i "$inventory" -m uri \
        -a "url=${scheme}://localhost:${port}/health method=GET status_code=200 validate_certs=false" \
        --one-line $(vault_args) &>/dev/null; do
        if [[ $(date +%s) -gt $deadline ]]; then
            log_error "Middleware health gate timed out."
            exit 1
        fi
        sleep 10
    done
    log_ok "Middleware ingress healthy."
}

# -- Rendered inventory path ----------------------------------------------------
RENDERED_INVENTORY="orchestration/rendered/inventory.yml"

# ==============================================================================
# MAIN DEPLOYMENT SEQUENCE
# ==============================================================================
main() {
    local mode_label; mode_label=$([[ "$OFFLINE_MODE" == "true" ]] && echo "AIR-GAPPED (OFFLINE)" || echo "ONLINE")
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      Sentinel Nexus -- Single-Shot Deployment         ║${NC}"
    echo -e "${CYAN}║      Mode: ${mode_label}$(printf '%*s' $((32 - ${#mode_label})) '')║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    log_info "Environment file : $ENV_FILE"
    INFRA_TARGET=$(python3 -c "import yaml; print(yaml.safe_load(open('$ENV_FILE')).get('infra_target','aws-ec2'))")
    log_info "Infrastructure   : $INFRA_TARGET"
    ENVIRONMENT=$(python3 -c "import yaml; print(yaml.safe_load(open('$ENV_FILE')).get('environment','unknown'))")
    log_info "Environment name : $ENVIRONMENT"
    log_info "Offline mode     : $OFFLINE_MODE"
    log_info "Endpoint count   : $(python3 -c "import yaml; print(yaml.safe_load(open('$ENV_FILE')).get('endpoint_count',0))")"
    log_info "Deployment tier  : $DEPLOYMENT_TIER"
    if [[ "$BARE_METAL_ENABLED" == "true" ]]; then
        log_warn "BARE METAL PATH -- NATS/Qdrant/Analytics/GPU/MinIO deploy as native binaries on RAID NVMe"
        log_warn "Run infrastructure/bare-metal/scripts/validate-bare-metal.sh on each node BEFORE proceeding"
    else
        log_info "CONTAINERISED PATH -- all services deployed as Podman Quadlets on VMs"
    fi
    echo ""

    check_prereqs
    setup_vault
    setup_ssh_key

    # Offline: install pre-downloaded Python/Ansible deps before any Ansible call
    [[ "$OFFLINE_MODE" == "true" ]] && install_offline_deps

    # -- Stage 1: Render templates --------------------------------------------
    echo ""
    log_info "━━ Stage 1/6 -- Render Templates ━━━━━━━━━━━━━━━━━━━━━━━━━━"
    chmod +x orchestration/scripts/01-render-templates.sh
    NEXUS_OFFLINE_MODE="$OFFLINE_MODE" ./orchestration/scripts/01-render-templates.sh "$ENV_FILE"
    source orchestration/rendered/global.env
    log_ok "Stage 1 complete."

    # -- Stage 2: Provision infrastructure + build inventory ------------------
    echo ""
    if [[ "$OFFLINE_MODE" == "true" ]]; then
        log_info "━━ Stage 2/6 -- Infrastructure  [OFFLINE -- skipping Terraform] ━━"
        # Offline: hosts must already exist; inventory must already be rendered
        # (by a prior online run or hand-crafted). Validate it exists.
        if [[ ! -f "$RENDERED_INVENTORY" ]]; then
            log_error "OFFLINE mode requires a pre-rendered inventory at: $RENDERED_INVENTORY"
            log_error "Either copy from a prior online deployment or render manually."
            exit 1
        fi
        log_ok "Stage 2 skipped -- using pre-rendered inventory: $RENDERED_INVENTORY"
    else
        log_info "━━ Stage 2/6 -- Provision Infrastructure ━━━━━━━━━━━━━━━━━━"
        chmod +x orchestration/scripts/02-provision-infra.sh
        ./orchestration/scripts/02-provision-infra.sh "$ENV_FILE"
        log_ok "Stage 2 complete -- inventory written to $RENDERED_INVENTORY."
    fi

    # Skip Ansible stages for EKS; Kubernetes path is separate
    if [[ "$INFRA_TARGET" == "aws-eks" ]]; then
        log_warn "infra_target=aws-eks: skipping Ansible stages. Apply middleware/deploy/kubernetes/ manifests manually."
        log_ok "Deployment handoff to Kubernetes complete."
        exit 0
    fi

    # -- SSH readiness gate ---------------------------------------------------
    wait_for_ssh "$RENDERED_INVENTORY"

    # -- Stage 2b (offline only): Load images on all hosts -------------------
    if [[ "$OFFLINE_MODE" == "true" ]]; then
        echo ""
        log_info "━━ Stage 2b/6 -- Load Bundle Images on All Hosts ━━━━━━━━━━"
        ansible all -i "$RENDERED_INVENTORY" \
            -m script \
            -a "${REPO_ROOT}/deployment_prep/scripts/10_load_images.sh" \
            $(vault_args) \
            -e nexus_offline=true \
            --become
        log_ok "Stage 2b complete -- images loaded on all target hosts."
    fi

    # -- Stage 3: Harden OS --------------------------------------------------
    echo ""
    log_info "━━ Stage 3/6 -- Harden Operating Systems ━━━━━━━━━━━━━━━━━━"
    chmod +x orchestration/scripts/03-harden-os.sh
    VAULT_PASS_FILE="$VAULT_PASS_FILE" NEXUS_OFFLINE_MODE="$OFFLINE_MODE" \
        NEXUS_BARE_METAL_ENABLED="$BARE_METAL_ENABLED" \
        NEXUS_DEPLOYMENT_TIER="$DEPLOYMENT_TIER" \
        ./orchestration/scripts/03-harden-os.sh
    log_ok "Stage 3 complete."

    # -- Stage 4: Deploy core services ---------------------------------------
    echo ""
    if [[ "$BARE_METAL_ENABLED" == "true" ]]; then
        log_info "━━ Stage 4/6 -- Deploy Core Infrastructure [BARE METAL] ━━━━"
        log_info "  NATS + Qdrant: native binary on RAID10 NVMe (no Podman)"
        log_info "  Analytics: DuckDB + PyTorch on 32TB RAID0 NVMe scratch"
    else
        log_info "━━ Stage 4/6 -- Deploy Core Infrastructure [CONTAINERISED] ━"
        log_info "  All services: Podman Quadlets on VMware VMs"
    fi
    chmod +x orchestration/scripts/04-deploy-core.sh
    VAULT_PASS_FILE="$VAULT_PASS_FILE" NEXUS_OFFLINE_MODE="$OFFLINE_MODE" \
        NEXUS_BARE_METAL_ENABLED="$BARE_METAL_ENABLED" \
        NEXUS_DEPLOYMENT_TIER="$DEPLOYMENT_TIER" \
        ./orchestration/scripts/04-deploy-core.sh
    log_ok "Stage 4 complete."

    # -- Core service health gates --------------------------------------------
    wait_for_nats    "$RENDERED_INVENTORY"
    wait_for_qdrant  "$RENDERED_INVENTORY"

    # -- Stage 5: Deploy middleware -------------------------------------------
    echo ""
    log_info "━━ Stage 5/6 -- Deploy Zero-Trust Middleware ━━━━━━━━━━━━━━"
    chmod +x orchestration/scripts/05-deploy-middleware.sh
    VAULT_PASS_FILE="$VAULT_PASS_FILE" NEXUS_OFFLINE_MODE="$OFFLINE_MODE" \
        NEXUS_BARE_METAL_ENABLED="$BARE_METAL_ENABLED" \
        NEXUS_DEPLOYMENT_TIER="$DEPLOYMENT_TIER" \
        ./orchestration/scripts/05-deploy-middleware.sh
    log_ok "Stage 5 complete."

    wait_for_middleware "$RENDERED_INVENTORY"

    # -- Stage 6: MLOps pipeline (optional) ----------------------------------
    if [[ "$SKIP_MLOPS" == "true" ]]; then
        log_warn "━━ Stage 6/6 -- MLOps Pipeline SKIPPED (--skip-mlops) ━━━━━"
    else
        echo ""
        log_info "━━ Stage 6/6 -- Sovereign MLOps Pipeline ━━━━━━━━━━━━━━━━━"
        chmod +x orchestration/scripts/06-trigger-mlops.sh
        NEXUS_OFFLINE_MODE="$OFFLINE_MODE" ./orchestration/scripts/06-trigger-mlops.sh
        log_ok "Stage 6 complete."
    fi

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Sentinel Nexus deployment complete -- all stages    ║${NC}"
    echo -e "${GREEN}║   Mode: ${mode_label}$(printf '%*s' $((43 - ${#mode_label})) '')║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

main "$@"

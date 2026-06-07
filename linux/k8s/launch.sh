#!/bin/bash
# ==============================================================================
# Falco Defense Toolkit -- Launcher
#
# A Kubernetes node defense bundle:
#   1. (optional) Hardens the host  -- CIS / NSA-CISA / STIG 2026 baselines
#   2. Generates TLS certificates if not present
#   3. Starts Falco + Sidekick + WebUI + Redis (runtime threat detection)
#   4. Builds and starts the Nexus transmitter (telemetry egress)
#
# Hardening and runtime detection are complementary layers: hardening shrinks
# the attack surface up front; Falco watches what's left at runtime.
#
# Usage:
#   ./launch.sh [--harden] [--harden-only] [--harden-dry-run]
#               [--harden-profile balanced|strict] [--harden-skip a,b,c]
#               [--rebuild] [--transmitter-only]
#
# Examples:
#   sudo ./launch.sh --harden                  # harden, then bring up Falco
#   sudo ./launch.sh --harden-dry-run          # preview hardening changes only
#   sudo ./launch.sh --harden-only --harden-profile strict
#   ./launch.sh                                # Falco stack only
# ==============================================================================

set -euo pipefail
cd "$(dirname "$0")"

RED='\033[1;31m'; GRN='\033[1;32m'; CYN='\033[1;36m'; YLW='\033[1;33m'; RST='\033[0m'

REBUILD=false
TX_ONLY=false
DO_HARDEN=false
HARDEN_ONLY=false

export HARDEN_DRY_RUN=false
export HARDEN_PROFILE=balanced
export HARDEN_SKIP=""

while [ $# -gt 0 ]; do
    case "$1" in
        --rebuild)          REBUILD=true ;;
        --transmitter-only) TX_ONLY=true ;;
        --harden)           DO_HARDEN=true ;;
        --harden-only)      DO_HARDEN=true; HARDEN_ONLY=true ;;
        --harden-dry-run)   DO_HARDEN=true; export HARDEN_DRY_RUN=true ;;
        --harden-profile)   export HARDEN_PROFILE="$2"; shift ;;
        --harden-skip)      export HARDEN_SKIP="$2"; shift ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo -e "${YLW}[!] Unknown arg: $1 (ignored)${RST}" ;;
    esac
    shift
done

# -- 0. Host Hardening ---------------------------------------------------------
# Runs first so the node is hardened before the detection stack comes online.
if [ "$DO_HARDEN" = true ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] Host hardening requires root. Re-run with sudo.${RST}"
        exit 1
    fi
    if [ ! -f host_hardening.sh ]; then
        echo -e "${RED}[!] host_hardening.sh not found next to launch.sh.${RST}"
        exit 1
    fi
    echo -e "${CYN}[*] Running host hardening (profile=${HARDEN_PROFILE}, dry_run=${HARDEN_DRY_RUN})…${RST}"
    # shellcheck source=host_hardening.sh
    source ./host_hardening.sh
    run_host_hardening

    if [ "$HARDEN_ONLY" = true ]; then
        echo -e "${GRN}[+] Hardening complete (--harden-only). Skipping Falco stack.${RST}"
        exit 0
    fi
fi

# -- 1. Certificate Setup -----------------------------------------------------
if [ ! -f certs/.env ]; then
    echo -e "${YLW}[!] certs/.env not found. Copying from .env.example${RST}"
    cp certs/.env.example certs/.env
    echo -e "${YLW}    Edit certs/.env with your values, then re-run.${RST}"
    exit 1
fi

# -- 2. Start Falco Stack -----------------------------------------------------
if [ "$TX_ONLY" = false ]; then
    echo -e "${CYN}[*] Starting Falco security stack...${RST}"

    if [ "$REBUILD" = true ]; then
        podman-compose down -v 2>/dev/null || true
        podman-compose build --no-cache
    fi

    podman-compose up -d

    echo -e "${GRN}[+] Falco stack running:${RST}"
    echo "    Falco sensor:  running (privileged)"
    echo "    Sidekick:      http://sidekick:2801 (internal)"
    echo "    WebUI:         http://127.0.0.1:2802"
    echo "    Redis:         internal"

    echo -e "${CYN}[*] Waiting for Falco log output...${RST}"
    LOG_VOL=$(podman volume inspect falco_falco_logs --format '{{.Mountpoint}}' 2>/dev/null || echo "/var/lib/containers/storage/volumes/falco_falco_logs/_data")
    for i in $(seq 1 30); do
        if [ -f "$LOG_VOL/falco-events.log" ]; then
            echo -e "${GRN}[+] Falco log detected at $LOG_VOL/falco-events.log${RST}"
            break
        fi
        sleep 2
    done
fi

# -- 3. Build & Start Transmitter ---------------------------------------------
echo -e "${CYN}[*] Building Falco transmitter...${RST}"

cd transmitter

if [ "$REBUILD" = true ]; then
    podman build --no-cache -t sentinel/falco_transmitter:v0.1 .
else
    podman build -t sentinel/falco_transmitter:v0.1 .
fi

LOG_VOL=$(podman volume inspect falco_falco_logs --format '{{.Mountpoint}}' 2>/dev/null || echo "")
SPOOL_DIR="${SPOOL_DIR:-/tmp/falco_transmitter_spool}"
mkdir -p "$SPOOL_DIR"

echo -e "${CYN}[*] Starting Falco transmitter container...${RST}"

podman run -d \
    --name falco-transmitter \
    --restart unless-stopped \
    --network host \
    -v "${LOG_VOL:-/var/log/falco}:/logs:ro" \
    -v "$SPOOL_DIR:/var/spool/falco_transmitter:rw" \
    -e FALCO_LOG_PATH=/logs/falco-events.log \
    -e NEXUS_GATEWAY_URL="${NEXUS_GATEWAY_URL:-https://nexus-edge:8080/api/v1/telemetry}" \
    -e NEXUS_AUTH_TOKEN="${NEXUS_AUTH_TOKEN:?Set NEXUS_AUTH_TOKEN}" \
    -e NEXUS_INTEGRITY_SECRET="${NEXUS_INTEGRITY_SECRET:?Set NEXUS_INTEGRITY_SECRET}" \
    -e SENSOR_ID="${SENSOR_ID:-falco-runtime-$(hostname -s)}" \
    -e BATCH_SIZE="${BATCH_SIZE:-500}" \
    -e BATCH_TIMEOUT_SECS="${BATCH_TIMEOUT_SECS:-10}" \
    -e METRICS_PORT="${METRICS_PORT:-9010}" \
    sentinel/falco_transmitter:v0.1

cd ..

echo -e "${GRN}[+] Falco transmitter running.${RST}"
echo "    Metrics: http://localhost:${METRICS_PORT:-9010}/metrics"
echo "    Spool:   $SPOOL_DIR"
echo ""
echo -e "${GRN}[+] Full Falco defense pipeline operational:${RST}"
echo "    Host hardening → Wire → Falco → JSON log → Transmitter → Parquet → Nexus Gateway"
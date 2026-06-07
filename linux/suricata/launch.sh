#!/bin/bash
# ==============================================================================
# Suricata IDS/IPS Stack Launcher
#
# 1. Selects mode (IDS passive  |  IPS inline) and inline method
# 2. Detects interface(s); for bridge mode, validates the second leg
# 3. Starts the Suricata container with the right caps + env
# 4. Waits for eve.json
# 5. Builds and starts the Nexus transmitter
#
# Usage:
#   ./launch.sh [--mode ids|ips] [--inline afpacket_bridge|nfqueue]
#               [--interface eth0] [--bridge-iface eth1]
#               [--policy detect|balanced|aggressive|paranoid]
#               [--home-net "[10.0.0.0/8,192.168.0.0/16]"]
#               [--fail-open] [--rebuild] [--transmitter-only]
#
# Examples:
#   ./launch.sh                                   # IDS (passive), balanced rules->alert
#   ./launch.sh --mode ips --policy balanced      # inline, block known-bad only
#   ./launch.sh --mode ips --inline afpacket_bridge --interface eth0 --bridge-iface eth1
#   ./launch.sh --mode ips --inline nfqueue --policy aggressive --fail-open
# ==============================================================================

set -euo pipefail
cd "$(dirname "$0")"

RED='\033[1;31m'; GRN='\033[1;32m'; CYN='\033[1;36m'; YLW='\033[1;33m'; RST='\033[0m'

REBUILD=false
TX_ONLY=false
IFACE=""
BRIDGE_IFACE=""
MODE="ids"
INLINE="afpacket_bridge"
POLICY="balanced"
HOME_NET_ARG=""
FAIL_OPEN="no"

while [ $# -gt 0 ]; do
    case "$1" in
        --rebuild)          REBUILD=true ;;
        --transmitter-only) TX_ONLY=true ;;
        --mode)             MODE="$2"; shift ;;
        --inline)           INLINE="$2"; shift ;;
        --interface)        IFACE="$2"; shift ;;
        --interface=*)      IFACE="${1#*=}" ;;
        --bridge-iface)     BRIDGE_IFACE="$2"; shift ;;
        --policy)           POLICY="$2"; shift ;;
        --home-net)         HOME_NET_ARG="$2"; shift ;;
        --fail-open)        FAIL_OPEN="yes" ;;
        -h|--help)          sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo -e "${YLW}[!] Unknown arg: $1 (ignored)${RST}" ;;
    esac
    shift
done

case "$MODE" in ids|ips) ;; *) echo -e "${RED}[!] --mode must be ids|ips${RST}"; exit 1 ;; esac
case "$INLINE" in afpacket_bridge|nfqueue) ;; *) echo -e "${RED}[!] --inline must be afpacket_bridge|nfqueue${RST}"; exit 1 ;; esac
case "$POLICY" in detect|balanced|aggressive|paranoid) ;; *) echo -e "${RED}[!] --policy must be detect|balanced|aggressive|paranoid${RST}"; exit 1 ;; esac

# -- 1. Detect Network Interface(s) -------------------------------------------
if [ -z "$IFACE" ]; then
    IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}' || echo "eth0")
fi
export CAPTURE_INTERFACE="$IFACE"

echo -e "${CYN}[*] Mode: ${MODE}  |  inline-method: ${INLINE}  |  policy: ${POLICY}${RST}"
echo -e "${CYN}[*] Capture interface: ${IFACE}${RST}"

if [ "$MODE" = "ips" ] && [ "$INLINE" = "afpacket_bridge" ]; then
    if [ -z "$BRIDGE_IFACE" ]; then
        echo -e "${RED}[!] afpacket_bridge IPS needs a second interface. Pass --bridge-iface ethX.${RST}"
        exit 1
    fi
    if ! ip link show "$BRIDGE_IFACE" >/dev/null 2>&1; then
        echo -e "${YLW}[!] Bridge iface ${BRIDGE_IFACE} not found on host; container may still see it if namespaced.${RST}"
    fi
    export BRIDGE_IFACE_B="$BRIDGE_IFACE"
    echo -e "${CYN}[*] Inline bridge: ${IFACE} <-> ${BRIDGE_IFACE}${RST}"
fi

# Export the knobs the compose file / entrypoint consume.
export IPS_MODE="$MODE"
export INLINE_METHOD="$INLINE"
export RULE_ACTION_POLICY="$POLICY"
export NFQ_FAIL_OPEN="$FAIL_OPEN"
[ -n "$HOME_NET_ARG" ] && export HOME_NET="$HOME_NET_ARG"

# -- 2. Start Suricata --------------------------------------------------------
if [ "$TX_ONLY" = false ]; then
    echo -e "${CYN}[*] Starting Suricata (${MODE}) ...${RST}"

    if [ "$REBUILD" = true ]; then
        podman-compose down -v 2>/dev/null || true
        podman-compose build --no-cache
    fi

    podman-compose up -d

    if [ "$MODE" = "ips" ]; then
        echo -e "${GRN}[+] Suricata INLINE/IPS active (policy=${POLICY}, fail-open=${FAIL_OPEN}).${RST}"
        echo -e "${YLW}    Known-bad is being BLOCKED. Verify with: tail -f \$LOG_VOL/eve.json | grep drop${RST}"
    else
        echo -e "${GRN}[+] Suricata IDS (passive) on ${IFACE}.${RST}"
    fi

    echo -e "${CYN}[*] Waiting for eve.json...${RST}"
    LOG_VOL=$(podman volume inspect suricata_suricata_logs --format '{{.Mountpoint}}' 2>/dev/null || echo "/var/lib/containers/storage/volumes/suricata_suricata_logs/_data")
    for i in $(seq 1 60); do
        if [ -f "$LOG_VOL/eve.json" ]; then
            echo -e "${GRN}[+] eve.json detected at $LOG_VOL/eve.json${RST}"
            break
        fi
        if [ "$i" -eq 60 ]; then
            echo -e "${YLW}[!] eve.json not found after 120s. Suricata may need traffic to generate output.${RST}"
        fi
        sleep 2
    done
fi

# -- 3. Build & Start Transmitter ---------------------------------------------
echo -e "${CYN}[*] Building Suricata transmitter...${RST}"
cd transmitter

if [ "$REBUILD" = true ]; then
    podman build --no-cache -t sentinel/suricata_transmitter:v0.1 .
else
    podman build -t sentinel/suricata_transmitter:v0.1 .
fi

LOG_VOL=$(podman volume inspect suricata_suricata_logs --format '{{.Mountpoint}}' 2>/dev/null || echo "")
SPOOL_DIR="${SPOOL_DIR:-/tmp/suricata_transmitter_spool}"
mkdir -p "$SPOOL_DIR"

podman rm -f suricata-transmitter 2>/dev/null || true

echo -e "${CYN}[*] Starting Suricata transmitter container...${RST}"
podman run -d \
    --name suricata-transmitter \
    --restart unless-stopped \
    --network host \
    -v "${LOG_VOL:-/var/log/suricata}:/var/log/suricata:ro" \
    -v "$SPOOL_DIR:/var/spool/suricata_transmitter:rw" \
    -e SURICATA_EVE_PATH=/var/log/suricata/eve.json \
    -e NEXUS_GATEWAY_URL="${NEXUS_GATEWAY_URL:-https://nexus-edge:8080/api/v1/telemetry}" \
    -e NEXUS_AUTH_TOKEN="${NEXUS_AUTH_TOKEN:?Set NEXUS_AUTH_TOKEN}" \
    -e NEXUS_INTEGRITY_SECRET="${NEXUS_INTEGRITY_SECRET:?Set NEXUS_INTEGRITY_SECRET}" \
    -e SENSOR_ID="${SENSOR_ID:-suricata-$(hostname -s)}" \
    -e BATCH_SIZE="${BATCH_SIZE:-1000}" \
    -e BATCH_TIMEOUT_SECS="${BATCH_TIMEOUT_SECS:-5}" \
    -e METRICS_PORT="${METRICS_PORT:-9011}" \
    sentinel/suricata_transmitter:v0.1

cd ..

echo -e "${GRN}[+] Suricata transmitter running.${RST}"
echo "    Metrics:   http://localhost:${METRICS_PORT:-9011}/metrics"
echo "    Spool:     $SPOOL_DIR"
echo "    Interface: $IFACE"
echo ""
echo -e "${GRN}[+] Full Suricata pipeline operational (${MODE}):${RST}"
echo "    Wire → Suricata → eve.json → Transmitter → Parquet → Nexus Gateway"
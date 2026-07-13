#!/bin/bash
# ==============================================================================
# Sentinel Nexus -- Enterprise Qdrant Initialization
# ==============================================================================

set -e
set -o pipefail

C_CYAN="\033[1;36m"
C_GREEN="\033[1;32m"
C_YELLOW="\033[1;33m"
C_RED="\033[1;31m"
C_RESET="\033[0m"

QDRANT_HOST=${QDRANT_HOST:-"qdrant"}
QDRANT_PORT=${QDRANT_PORT:-"6333"}
COLLECTION_NAME=${COLLECTION_NAME:-"ueba_vectors"}
QDRANT_API_URL="http://${QDRANT_HOST}:${QDRANT_PORT}"

echo -e "${C_CYAN}[*] Initializing Sentinel Nexus Vector Schema Pipeline${C_RESET}"

# ── 1. Readiness Polling Loop ─────────────────────────────────────────────────
echo -e "${C_CYAN}[*] Polling Qdrant readiness probe at ${QDRANT_API_URL}/readyz...${C_RESET}"

MAX_RETRIES=30
RETRY_COUNT=0

while true; do
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${QDRANT_API_URL}/readyz" || echo "000")

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e "${C_GREEN}[+] Qdrant is online and ready to accept connections.${C_RESET}"
        break
    fi

    if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
        echo -e "${C_RED}[!] CRITICAL: Qdrant failed to become ready after 30 seconds. Exiting.${C_RESET}"
        exit 1
    fi

    echo -e "${C_YELLOW}  └─ Waiting for Qdrant... (Attempt $((RETRY_COUNT+1))/$MAX_RETRIES)${C_RESET}"
    sleep 2
    ((RETRY_COUNT++))
done

# ── 2. Idempotency Check ──────────────────────────────────────────────────────
echo -e "${C_CYAN}[*] Verifying collection state: '${COLLECTION_NAME}'...${C_RESET}"

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${QDRANT_API_URL}/collections/${COLLECTION_NAME}")

if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e "${C_GREEN}[+] Collection '${COLLECTION_NAME}' already exists. Ensuring indexes are current...${C_RESET}"
    # Fall through to index creation (idempotent)
else
    # ── 3. Enterprise Schema Implementation ────────────────────────────────────
    echo -e "${C_CYAN}[*] Collection not found. Provisioning '${COLLECTION_NAME}' for high-throughput...${C_RESET}"

    HTTP_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X PUT "${QDRANT_API_URL}/collections/${COLLECTION_NAME}" \
      -H 'Content-Type: application/json' \
      --data-raw '{
        "vectors": {
          "c2_math": {
            "size": 8,
            "distance": "Cosine",
            "on_disk": true
          },
          "sentinel_math": {
            "size": 5,
            "distance": "Cosine",
            "on_disk": true
          },
          "windows_math": {
            "size": 6,
            "distance": "Cosine",
            "on_disk": true
          },
          "deepsensor_math": {
            "size": 4,
            "distance": "Cosine",
            "on_disk": true
          },
          "trellix_math": {
            "size": 6,
            "distance": "Cosine",
            "on_disk": true
          },
          "cloud_flow": {
            "size": 5,
            "distance": "Cosine",
            "on_disk": true
          },
          "network_tap": {
            "size": 8,
            "distance": "Cosine",
            "on_disk": true
          }
        },
        "shard_number": 6,
        "replication_factor": 2,
        "on_disk_payload": true,
        "wal_config": {
          "wal_capacity_mb": 32,
          "wal_segments_ahead": 0
        },
        "hnsw_config": {
          "m": 16,
          "ef_construct": 100,
          "on_disk": true
        },
        "optimizers_config": {
          "default_segment_number": 4,
          "max_optimization_threads": 2,
          "memmap_threshold": 20000,
          "indexing_threshold": 50000
        }
    }')

    HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed -e 's/HTTP_STATUS\:.*//g')
    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e "${C_GREEN}[+] Schema provisioned successfully.${C_RESET}"
    else
        echo -e "${C_RED}[!] CRITICAL: Failed to create collection. HTTP ${HTTP_STATUS}${C_RESET}"
        echo -e "${C_RED}Response: ${HTTP_BODY}${C_RESET}"
        exit 1
    fi
fi

# ── 4. Payload Field Index Enforcement ─────────────────────────────

echo -e "${C_CYAN}[*] Enforcing KEYWORD payload indexes for temporal graph queries...${C_RESET}"

for FIELD_NAME in "endpoint_id" "source_type" "vector_name"; do
    HTTP_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X PUT \
        "${QDRANT_API_URL}/collections/${COLLECTION_NAME}/index" \
        -H 'Content-Type: application/json' \
        --data-raw "{
            \"field_name\": \"${FIELD_NAME}\",
            \"field_schema\": \"keyword\"
        }")

    HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

    if [ "$HTTP_STATUS" -eq 200 ]; then
        echo -e "${C_GREEN}  [+] Index '${FIELD_NAME}' → KEYWORD: OK${C_RESET}"
    else
        echo -e "${C_YELLOW}  [~] Index '${FIELD_NAME}' returned HTTP ${HTTP_STATUS} (may already exist)${C_RESET}"
    fi
done

HTTP_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X PUT \
    "${QDRANT_API_URL}/collections/${COLLECTION_NAME}/index" \
    -H 'Content-Type: application/json' \
    --data-raw '{
        "field_name": "timestamp_epoch",
        "field_schema": "float"
    }')

HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTP_STATUS://')

if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e "${C_GREEN}  [+] Index 'timestamp_epoch' → FLOAT: OK${C_RESET}"
else
    echo -e "${C_YELLOW}  [~] Index 'timestamp_epoch' returned HTTP ${HTTP_STATUS} (may already exist)${C_RESET}"
fi

echo -e "${C_GREEN}[+] Initialization complete. Payload indexes enforced.${C_RESET}"
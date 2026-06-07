#!/bin/bash
# Lab 4: Qdrant collection initialization for ueba_vectors
# Matches nexus-lab4.toml named_vectors (windows_math=6D, trellix_math=4D, etc.)

set -e

QDRANT_HOST=${QDRANT_HOST:-"qdrant"}
QDRANT_PORT=${QDRANT_PORT:-"6333"}
COLLECTION=${COLLECTION_NAME:-"ueba_vectors"}
BASE="http://${QDRANT_HOST}:${QDRANT_PORT}"

echo "[*] Waiting for Qdrant at ${BASE}/readyz ..."
for i in $(seq 1 40); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/readyz" || echo "000")
    [ "$STATUS" -eq 200 ] && { echo "[+] Qdrant ready."; break; }
    [ "$i" -eq 40 ] && { echo "[!] Qdrant not ready after 80s."; exit 1; }
    sleep 2
done

echo "[*] Checking collection '${COLLECTION}' ..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/collections/${COLLECTION}")
if [ "$STATUS" -eq 200 ]; then
    echo "[+] Collection already exists -- skipping creation."
else
    echo "[*] Creating collection '${COLLECTION}' ..."
    curl -sf -X PUT "${BASE}/collections/${COLLECTION}" \
      -H 'Content-Type: application/json' \
      -d '{
        "vectors": {
          "windows_math":    { "size": 6, "distance": "Cosine", "on_disk": true },
          "sentinel_math":   { "size": 5, "distance": "Cosine", "on_disk": true },
          "c2_math":         { "size": 8, "distance": "Cosine", "on_disk": true },
          "deepsensor_math": { "size": 4, "distance": "Cosine", "on_disk": true },
          "trellix_math":    { "size": 4, "distance": "Cosine", "on_disk": true },
          "cloud_flow":      { "size": 5, "distance": "Cosine", "on_disk": true },
          "network_tap":     { "size": 8, "distance": "Cosine", "on_disk": true }
        },
        "hnsw_config": { "m": 8, "ef_construct": 50, "on_disk": true },
        "optimizers_config": { "default_segment_number": 2 }
      }' && echo "[+] Collection created." || { echo "[!] Creation failed."; exit 1; }
fi

echo "[*] Enforcing payload indexes ..."
for FIELD in "endpoint_id" "source_type" "vector_name" "nexus_sensor_id"; do
    curl -sf -X PUT "${BASE}/collections/${COLLECTION}/index" \
      -H 'Content-Type: application/json' \
      -d "{\"field_name\":\"${FIELD}\",\"field_schema\":\"keyword\"}" \
      && echo "  [+] keyword index: ${FIELD}" \
      || echo "  [~] index ${FIELD} may already exist"
done

curl -sf -X PUT "${BASE}/collections/${COLLECTION}/index" \
  -H 'Content-Type: application/json' \
  -d '{"field_name":"anomaly_score","field_schema":"float"}' \
  && echo "  [+] float index: anomaly_score" || true

curl -sf -X PUT "${BASE}/collections/${COLLECTION}/index" \
  -H 'Content-Type: application/json' \
  -d '{"field_name":"timestamp_epoch","field_schema":"float"}' \
  && echo "  [+] float index: timestamp_epoch" || true

echo "[+] Lab 4 Qdrant initialization complete."

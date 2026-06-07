#!/bin/bash

if command -v podman >/dev/null 2>&1; then
    CONTAINER_CLI="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CLI="docker"
else
    echo "[-] FATAL: Neither Podman nor Docker was found in PATH."
    exit 1
fi

mkdir -p ./reports
VOLUME_NAME=$($CONTAINER_CLI volume ls -q | grep "sentinel-data" | head -n 1)

if [ -z "$VOLUME_NAME" ]; then
    echo "[-] FATAL: Could not locate the sentinel-data volume."
    exit 1
fi

echo "[*] Exporting ALL UEBA Baselines from volume: $VOLUME_NAME"

$CONTAINER_CLI run --rm -i \
  -v "$VOLUME_NAME:/var/log/linux-sentinel:ro" \
  -v "$(pwd)/reports:/workspace" \
  alpine:3.23 sh -c 'apk add --no-cache python3 --quiet && python3 -' << 'EOF'
import sqlite3
import os
import json
from datetime import datetime

DB_PATH = "/var/log/linux-sentinel/baselines.db"
REPORT_PATH = "/workspace/ueba_full_export.txt"

if not os.path.exists(DB_PATH):
    print(f"[-] Error: Database not found at {DB_PATH}")
    exit(1)

try:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM ueba_process_profiles")
    rows = cursor.fetchall()

    with open(REPORT_PATH, "w") as f:
        f.write("===============================================================================\n")
        f.write(f"LINUX SENTINEL - FULL UEBA BASELINE REPORT\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Total Profiles: {len(rows)}\n")
        f.write("===============================================================================\n\n")

        if not rows:
            f.write("[!] No profiles found in ueba_process_profiles.\n")
        else:
            for i, row in enumerate(rows, 1):
                f.write(f"ENTRY #{i}\n")
                f.write(f"{'-' * 40}\n")
                f.write(f"PROCESS HASH:     {row['process_hash']}\n")
                f.write(f"EVENT COUNT:      {row['event_count']}\n")
                f.write(f"MEAN DELTA (ns):  {row['mean_delta']:.2f}\n")
                f.write(f"M2 DELTA:         {row['m2_delta']:.2f}\n")
                f.write(f"LAST SEEN (ns):   {row['last_seen_ns']}\n")

                # Format the JSON vector data for readability
                try:
                    vectors = json.loads(row['serialized_recent_events'])
                    f.write(f"FOREST SAMPLES:   {len(vectors)}\n")
                    f.write(f"RAW VECTORS:\n")
                    for v in vectors:
                        f.write(f"  - {v}\n")
                except:
                    f.write(f"RAW VECTORS:      [Error parsing JSON payload]\n")

                f.write("\n")

    print(f"[+] SUCCESS: {len(rows)} profiles exported to ./reports/ueba_full_export.txt")

except Exception as e:
    print(f"[-] Database Error: {e}")
EOF
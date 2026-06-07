#!/bin/bash
# ==============================================================================
# Script:  generate_report.sh
# Purpose: Extracts high-fidelity signature detections from Linux Sentinel.
#          Deduplicates repeating alerts, keeping only the earliest occurrence,
#          and exports the data to a cleanly formatted text table.
# ==============================================================================

if command -v podman >/dev/null 2>&1; then
    CONTAINER_CLI="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CLI="docker"
else
    echo "[-] FATAL: Neither Podman nor Docker was found in PATH."
    exit 1
fi

echo "[*] Initializing report extraction..."

mkdir -p ./reports
echo "[*] Output directory secured at ./reports/"

VOLUME_NAME=$($CONTAINER_CLI volume ls -q | grep "sentinel-data" | head -n 1)

if [ -z "$VOLUME_NAME" ]; then
    echo "[-] FATAL: Could not locate the sentinel-data volume. Is the orchestration running?"
    exit 1
fi

echo "[*] Found active database volume: $VOLUME_NAME"
echo "[*] Spawning ephemeral Alpine container for read-only analysis..."

$CONTAINER_CLI run --rm -i \
  -v "$VOLUME_NAME:/var/log/linux-sentinel:rw" \
  -v "$(pwd)/reports:/workspace" \
  alpine:3.23 sh -c 'apk add --no-cache python3 sqlite --quiet && python3 -' << 'EOF'
import sqlite3
import os

DB_PATH = "/var/log/linux-sentinel/sentinel.db"
LOG_PATH = "/workspace/signature_detections.log"

if not os.path.exists(DB_PATH):
    print(f"[-] FATAL: Database not found at {DB_PATH}")
    exit(1)

conn = sqlite3.connect(f"file:{DB_PATH}", uri=True, timeout=15.0)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# -------------------------------------------------------------------
# DEDUPLICATION LOGIC (SQLite Window Functions)
# Groups by process (comm), technique, and message.
# dedupe_count: Totals the number of times this exact event fired.
# rn: Ranks them by time. WHERE rn = 1 extracts only the earliest.
# -------------------------------------------------------------------
query = """
WITH RankedEvents AS (
    SELECT
        *,
        COUNT(event_id) OVER(PARTITION BY comm, mitre_technique, message) as dedupe_count,
        ROW_NUMBER() OVER(PARTITION BY comm, mitre_technique, message ORDER BY timestamp ASC) as rn
    FROM events
    WHERE mitre_technique NOT LIKE '%ML Anomaly%'
      AND message NOT LIKE '%Isolation Forest%'
      AND (
          message LIKE '%Sigma%'
          OR message LIKE '%YARA%'
          OR message LIKE '%Reflective%'
          OR message LIKE '%Critical%'
          OR mitre_technique LIKE '%T%'
      )
)
SELECT
    datetime(timestamp, 'unixepoch', 'localtime') as local_time,
    dedupe_count,
    *
FROM RankedEvents
WHERE rn = 1
ORDER BY timestamp DESC
"""

try:
    cursor.execute(query)
    rows = cursor.fetchall()

    with open(LOG_PATH, "w") as f:
        if not rows:
            f.write("[-] No signature detections found in the database.\n")
            print("[-] No signature detections found. Empty log written to ./reports/signature_detections.log")
        else:
            # Exclude internal/tracking columns from the final text table
            exclude_cols = ("timestamp", "rn")
            columns = [key for key in rows[0].keys() if key not in exclude_cols]

            # Define fixed widths for clean table formatting
            widths = {
                "local_time": 20, "dedupe_count": 8, "event_id": 36, "level": 10, "mitre_tactic": 25,
                "mitre_technique": 35, "pid": 8, "ppid": 8, "uid": 5,
                "container_id": 14, "container_name": 16,
                "user_name": 12, "parent_comm": 16,
                "comm": 16, "command_line": 40, "target_file": 30,
                "dest_ip": 16, "source_port": 12, "dest_port": 10,
                "shannon_entropy": 8, "execution_velocity": 8, "tuple_rarity": 8,
                "path_depth": 5, "anomaly_score": 6, "message": 80, "transmitted": 5
            }

            # Generate Header
            header_str = " | ".join([f"{col.upper():{widths.get(col, 15)}}" for col in columns])
            f.write(f"[+] Found {len(rows)} unique signature signatures (Duplicates collapsed to earliest event)\n")
            f.write("=" * len(header_str) + "\n")
            f.write(header_str + "\n")
            f.write("-" * len(header_str) + "\n")

            # Generate Rows
            for row in rows:
                row_vals = []
                for col in columns:
                    val = row[col]
                    if val is None:
                        val = ""
                    elif isinstance(val, float):
                        val = f"{val:.2f}"
                    elif col == "dedupe_count":
                        val = f"x{val}" # Formats as 'x12' for duplicates

                    # Truncate string to avoid breaking the table layout
                    val_str = str(val)[:widths.get(col, 15)]
                    row_vals.append(f"{val_str:{widths.get(col, 15)}}")

                f.write(" | ".join(row_vals) + "\n")

    print(f"[+] SUCCESS: Extracted {len(rows)} unique signature alerts.")
    print(f"[+] Report exported to: ./reports/signature_detections.log")

except sqlite3.Error as e:
    print(f"[-] SQLite Evaluation Error: {e}")
    exit(1)
EOF
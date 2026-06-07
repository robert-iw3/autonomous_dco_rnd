#!/bin/bash
set -e

cleanup() {
    echo "[+] Terminating daemon processes gracefully..."
    kill -TERM $PID_ML $PID_INGEST $PID_HUNTER $PID_DEFENDER $PID_NEXUS 2>/dev/null || true
    wait
    exit 0
}
trap cleanup SIGTERM SIGINT

# Extract deployment mode (POSIX-safe for BusyBox grep)
DEPLOY_MODE=$(sed -n 's/^mode[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' /app/config.toml)
DEPLOY_MODE="${DEPLOY_MODE:-full}"
echo "[+] Starting C2 Sensor Core Pipeline (Profile: ${DEPLOY_MODE^^})..."

DB_PATH="/app/data/baseline.db"
mkdir -p "$(dirname "$DB_PATH")"

# --- Universal Schema Migration ------------------------------------------
# Runs for ALL deployment modes before any daemon touches SQLite.
# Uses Python stdlib sqlite3 (no sqlite3 CLI dependency required).
#
# Fresh DB  → CREATE TABLE IF NOT EXISTS builds it from scratch.
# Existing  → Each column is checked via PRAGMA table_info; missing
#             columns are ALTERed in. To add a future column: add it to
#             the CREATE TABLE and to the MIGRATIONS list below.
# -------------------------------------------------------------------------
echo "[+] Initializing database schema..."
python3 - "$DB_PATH" <<'MIGRATE'
import sqlite3, sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.executescript("""
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL,
    process_name    TEXT    DEFAULT 'unknown',
    dst_ip          TEXT    DEFAULT '0.0.0.0',
    dst_port        INTEGER DEFAULT 0,
    interval        REAL    DEFAULT 0.0,
    cv              REAL    DEFAULT 0.0,
    outbound_ratio  REAL    DEFAULT 0.0,
    entropy         REAL    DEFAULT 0.0,
    packet_size_mean REAL   DEFAULT 0.0,
    packet_size_std  REAL   DEFAULT 0.0,
    packet_size_min  INTEGER DEFAULT 0,
    packet_size_max  INTEGER DEFAULT 0,
    packet_count    INTEGER DEFAULT 0,
    mitre_tactic    TEXT    DEFAULT 'Unknown',
    pid             INTEGER DEFAULT 0,
    uid             INTEGER DEFAULT 0,
    cmd_entropy     REAL    DEFAULT 0.0,
    suppressed      INTEGER DEFAULT 0,
    score           INTEGER DEFAULT 0,
    cmd_snippet     TEXT    DEFAULT '',
    process_tree    TEXT    DEFAULT '',
    masquerade_detected INTEGER DEFAULT 0,
    reasons         TEXT    DEFAULT '[]',
    mitre_technique TEXT    DEFAULT '',
    mitre_name      TEXT    DEFAULT '',
    description     TEXT    DEFAULT '',
    ml_result       TEXT    DEFAULT NULL,
    process_hash    TEXT    DEFAULT '',
    dns_query       TEXT    DEFAULT '',
    event_type      TEXT    DEFAULT 'unknown',
    dns_flags       INTEGER DEFAULT 0,
    ja3_hash        TEXT    DEFAULT '',
    sensor_id       TEXT    DEFAULT 'unknown'
);

CREATE INDEX IF NOT EXISTS idx_flows_score_ts ON flows(score, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp);
""")

MIGRATIONS = [
    ("packet_count",        "INTEGER DEFAULT 0"),
    ("packet_size_mean",    "REAL DEFAULT 0.0"),
    ("packet_size_std",     "REAL DEFAULT 0.0"),
    ("packet_size_min",     "INTEGER DEFAULT 0"),
    ("packet_size_max",     "INTEGER DEFAULT 0"),
    ("score",               "INTEGER DEFAULT 0"),
    ("cmd_snippet",         "TEXT DEFAULT ''"),
    ("process_tree",        "TEXT DEFAULT ''"),
    ("masquerade_detected", "INTEGER DEFAULT 0"),
    ("reasons",             "TEXT DEFAULT '[]'"),
    ("mitre_technique",     "TEXT DEFAULT ''"),
    ("mitre_name",          "TEXT DEFAULT ''"),
    ("description",         "TEXT DEFAULT ''"),
    ("ml_result",           "TEXT DEFAULT NULL"),
    ("process_hash",        "TEXT DEFAULT ''"),
    ("dns_query",           "TEXT DEFAULT ''"),
    ("event_type",          "TEXT DEFAULT 'unknown'"),
    ("dns_flags",           "INTEGER DEFAULT 0"),
    ("ja3_hash",            "TEXT DEFAULT ''"),
    ("sensor_id",           "TEXT DEFAULT 'unknown'"),
]

existing = {row[1] for row in conn.execute("PRAGMA table_info(flows)").fetchall()}

for col_name, col_def in MIGRATIONS:
    if col_name not in existing:
        print(f"[+] Migrating: ALTER TABLE flows ADD COLUMN {col_name} {col_def}")
        conn.execute(f"ALTER TABLE flows ADD COLUMN {col_name} {col_def}")

conn.commit()
conn.close()
print("[+] Schema migration complete")
MIGRATE

# --- Mode-specific daemon launch -----------------------------------------

if [[ "$DEPLOY_MODE" == "collector" ]]; then
    echo "[+] Collector database ready"

    echo "[+] Initializing Rust eBPF Ingest (telemetry_ingest)..."
    telemetry_ingest &
    PID_INGEST=$!

    echo "[+] Initializing Nexus Forwarder (nexus_forwarder.py)..."
    python3 /app/python_engine/nexus_forwarder.py &
    PID_NEXUS=$!

else
    # --- STANDARD / FULL: baseline_learner handles ML baselines ---
    (
        while true; do
            python3 /app/python_engine/baseline_learner.py &
            ML_PID=$!
            sleep 86400
            echo "[+] Performing daily graceful restart of ML engine..."
            kill -TERM $ML_PID
            wait $ML_PID 2>/dev/null || true
        done
    ) &
    PID_ML=$!

    echo "[+] Initializing Rust eBPF Ingest (telemetry_ingest)..."
    telemetry_ingest &
    PID_INGEST=$!

    echo "[+] Initializing Rust Heuristics (core_hunter)..."
    core_hunter &
    PID_HUNTER=$!

    if [[ "$DEPLOY_MODE" == "full" ]]; then
        echo "[+] Initializing Nexus Forwarder (nexus_forwarder.py)..."
        python3 /app/python_engine/nexus_forwarder.py &
        PID_NEXUS=$!

        echo "[+] Initializing Rust Active Defender (active_defender)..."
        active_defender &
        PID_DEFENDER=$!
    fi
fi

echo "[+] All Core Daemons Active. Tailing outputs..."
wait -n $PID_ML $PID_NEXUS $PID_INGEST $PID_HUNTER $PID_DEFENDER 2>/dev/null

EXIT_CODE=$?
echo "[-] FATAL: A core daemon exited unexpectedly. Shutting down container."
exit $EXIT_CODE
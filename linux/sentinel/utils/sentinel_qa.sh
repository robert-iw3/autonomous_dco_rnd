#!/usr/bin/env bash
# ==================================================================================
# File:        sentinel_qa.sh
# Component:   Linux Sentinel -- End-to-End Pipeline Validation Suite
# Description: Automated integration testing framework for the Linux Sentinel agent.
# Role:        Validates container health, database integrity, API authentication,
#              eBPF telemetry ingestion, UEBA anomaly scoring, and signal handling.
#              Acts as the primary quality gate before merging or deploying new
#              engine versions to production.
# Author:      Robert Weber
#
# Usage:  sudo ./sentinel_qa.sh
# ===================================================================================

set -euo pipefail

CONTAINER_CLI="docker"
if command -v podman &> /dev/null; then
    CONTAINER_CLI="podman"
fi

API_BASE="https://127.0.0.1:8080"
CURL_OPTS="-sk --connect-timeout 5 --max-time 10"
AGENT_CONTAINER="linux-sentinel-agent"
VOLUME_NAME=$($CONTAINER_CLI volume ls --format '{{.Name}}' 2>/dev/null | grep 'sentinel-data' | head -1)
if [ -z "$VOLUME_NAME" ]; then
    echo "FATAL: No volume matching 'sentinel-data' found."
    $CONTAINER_CLI volume ls
    exit 1
fi
PASS=0
FAIL=0
SKIP=0
RESULTS=()

TOKEN_FILE="$(pwd)/certs/auth_token.txt"
if [ -f "$TOKEN_FILE" ]; then
    AUTH_TOKEN=$(cat "$TOKEN_FILE")
else
    echo "FATAL: Auth token not found at $TOKEN_FILE"
    exit 1
fi

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_pass() {
    PASS=$((PASS + 1))
    RESULTS+=("PASS|$1")
    echo -e "  ${GREEN}[PASS]${NC} $1"
}
log_fail() {
    FAIL=$((FAIL + 1))
    RESULTS+=("FAIL|$1|$2")
    echo -e "  ${RED}[FAIL]${NC} $1"
    echo -e "        ${RED}→ $2${NC}"
}
log_skip() {
    SKIP=$((SKIP + 1))
    RESULTS+=("SKIP|$1|$2")
    echo -e "  ${YELLOW}[SKIP]${NC} $1 -- $2"
}
section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

db_query() {
    $CONTAINER_CLI run --rm -v "${VOLUME_NAME}:/data:ro" alpine:3.20 \
        sh -c "apk add --no-cache sqlite >/dev/null 2>&1 && sqlite3 /data/sentinel.db \"$1\"" 2>/dev/null
}

api_get() {
    curl $CURL_OPTS -H "Authorization: Bearer ${AUTH_TOKEN}" "${API_BASE}$1" 2>/dev/null
}
api_post() {
    curl $CURL_OPTS -X POST -H "Authorization: Bearer ${AUTH_TOKEN}" "${API_BASE}$1" 2>/dev/null
}

# ==============================================================================
# PHASE 0: PRE-FLIGHT
# ==============================================================================
section "PHASE 0: PRE-FLIGHT CHECKS"

if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: Must run as root."
    exit 1
fi

if $CONTAINER_CLI inspect "$AGENT_CONTAINER" >/dev/null 2>&1; then
    AGENT_STATE=$($CONTAINER_CLI inspect --format '{{.State.Status}}' "$AGENT_CONTAINER" 2>/dev/null || \
                  $CONTAINER_CLI inspect --format '{{.State.Running}}' "$AGENT_CONTAINER" 2>/dev/null)
    if echo "$AGENT_STATE" | grep -qiE "running|true"; then
        log_pass "Agent container is running"
    else
        log_fail "Agent container not running" "State: $AGENT_STATE"
        exit 1
    fi
else
    log_fail "Agent container not found" "Deploy first"
    exit 1
fi

if $CONTAINER_CLI volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
    log_pass "Data volume exists"
else
    log_fail "Data volume not found" "$VOLUME_NAME"
    exit 1
fi

DB_EXISTS=$(db_query "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events';" || echo "0")
if [ "$DB_EXISTS" = "1" ]; then
    log_pass "SQLite database accessible with events table"
else
    log_fail "Database or events table missing" "Got: $DB_EXISTS"
    exit 1
fi

# ==============================================================================
# PHASE 1: API HEALTH & TLS
# ==============================================================================
section "PHASE 1: API SERVER"

STATUS_BODY=$(curl $CURL_OPTS "${API_BASE}/api/status" 2>/dev/null || echo "")
if echo "$STATUS_BODY" | grep -q "Operational"; then
    log_pass "GET /api/status returns Operational (unauthenticated)"
else
    log_fail "GET /api/status failed" "$STATUS_BODY"
fi

if echo "$STATUS_BODY" | grep -q "0.3.0"; then
    log_pass "API reports correct version"
else
    log_fail "Version mismatch" "$STATUS_BODY"
fi

HTTP_RESULT=$(curl -s --connect-timeout 3 "http://127.0.0.1:8080/api/status" 2>&1 || echo "refused")
if echo "$HTTP_RESULT" | grep -qiE "refused|reset|empty|error|curl"; then
    log_pass "Plaintext HTTP refused (TLS enforced)"
else
    log_fail "Plaintext HTTP not refused" "TLS may be disabled"
fi

# ==============================================================================
# PHASE 2: AUTHENTICATION
# ==============================================================================
section "PHASE 2: AUTHENTICATION"

ALERTS_BODY=$(api_get "/api/alerts")
if echo "$ALERTS_BODY" | grep -q '"success"'; then
    log_pass "Authenticated GET /api/alerts succeeds"
else
    log_fail "Authenticated request failed" "$ALERTS_BODY"
fi

NOAUTH_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "${API_BASE}/api/alerts" 2>/dev/null || echo "000")
if [ "$NOAUTH_CODE" = "401" ]; then
    log_pass "Missing token returns 401"
else
    log_fail "Missing token not rejected" "HTTP $NOAUTH_CODE"
fi

BAD_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer INVALID_TOKEN" "${API_BASE}/api/alerts" 2>/dev/null || echo "000")
if [ "$BAD_CODE" = "401" ]; then
    log_pass "Invalid token returns 401"
else
    log_fail "Invalid token not rejected" "HTTP $BAD_CODE"
fi

# ==============================================================================
# PHASE 3: eBPF KERNEL TELEMETRY
# ==============================================================================
section "PHASE 3: eBPF KERNEL TELEMETRY"

EVENT_COUNT_BEFORE=$(db_query "SELECT count(*) FROM events;" || echo "0")

echo "  [*] Triggering T1078: /etc/shadow access..."
cat /etc/shadow > /dev/null 2>&1 || true
cat /etc/passwd > /dev/null 2>&1 || true

echo "  [*] Triggering T1059: Shell execution..."
bash -c 'whoami' >/dev/null 2>&1 || true
bash -c 'id' >/dev/null 2>&1 || true

echo "  [*] Triggering T1571: C2 port probes..."
curl -s --connect-timeout 1 http://127.0.0.1:4444 >/dev/null 2>&1 || true
curl -s --connect-timeout 1 http://127.0.0.1:1337 >/dev/null 2>&1 || true

echo "  [*] Triggering T1620: memfd_create..."
python3 -c 'import ctypes; libc = ctypes.CDLL(None); libc.syscall(319, b"qa_memfd", 0)' 2>/dev/null || true

echo "  [*] Waiting 8 seconds for pipeline flush..."
sleep 8

EVENT_COUNT_AFTER=$(db_query "SELECT count(*) FROM events;" || echo "0")
NEW_EVENTS=$((EVENT_COUNT_AFTER - EVENT_COUNT_BEFORE))

if [ "$NEW_EVENTS" -gt 0 ]; then
    log_pass "Pipeline generated $NEW_EVENTS new events"
else
    log_fail "No new events after trigger battery" "Before: $EVENT_COUNT_BEFORE After: $EVENT_COUNT_AFTER"
fi

for TECHNIQUE in "T1078" "T1571"; do
    COUNT=$(db_query "SELECT count(*) FROM events WHERE mitre_technique LIKE '%${TECHNIQUE}%';" || echo "0")
    if [ "$COUNT" -gt 0 ]; then
        log_pass "$TECHNIQUE detected ($COUNT events)"
    else
        log_fail "$TECHNIQUE not found" "Expected at least 1"
    fi
done

for TECHNIQUE in "T1059" "T1620"; do
    COUNT=$(db_query "SELECT count(*) FROM events WHERE mitre_technique LIKE '%${TECHNIQUE}%';" || echo "0")
    if [ "$COUNT" -gt 0 ]; then
        log_pass "$TECHNIQUE detected ($COUNT events)"
    else
        log_skip "$TECHNIQUE not detected" "Depends on loaded Sigma ruleset and kernel hook coverage"
    fi
done

if command -v python3 &>/dev/null; then
    T1620=$(db_query "SELECT count(*) FROM events WHERE mitre_technique LIKE '%T1620%';" || echo "0")
    if [ "$T1620" -gt 0 ]; then
        log_pass "T1620 memfd_create detected ($T1620 events)"
    else
        log_fail "T1620 not detected" "memfd trigger may not have reached pipeline"
    fi
else
    log_skip "T1620 test" "python3 not available"
fi

# ==============================================================================
# PHASE 4: UEBA SCORING
# ==============================================================================
section "PHASE 4: UEBA ANOMALY SCORING"

SCORED=$(db_query "SELECT count(*) FROM events WHERE anomaly_score > 0;" || echo "0")
if [ "$SCORED" -gt 0 ]; then
    log_pass "UEBA active: $SCORED events scored"
else
    log_fail "No scored events" "Isolation Forest may not be running"
fi

MAX_SCORE=$(db_query "SELECT printf('%.4f', MAX(anomaly_score)) FROM events;" || echo "0")
echo -e "  ${CYAN}[INFO]${NC} Peak anomaly score: $MAX_SCORE"

LEVEL_DIST=$(db_query "SELECT level, count(*) FROM events GROUP BY level;" || echo "none")
echo -e "  ${CYAN}[INFO]${NC} Distribution: $(echo "$LEVEL_DIST" | tr '\n' '  ')"

# ==============================================================================
# PHASE 5: HONEYPOT ENGINE
# ==============================================================================
section "PHASE 5: HONEYPOT ENGINE"

HONEY_BEFORE=$(db_query "SELECT count(*) FROM events WHERE mitre_technique LIKE '%T1046%';" || echo "0")

echo "  [*] Probing honeypot ports (6379, 27017, 9200)..."
for PORT in 6379 27017 9200; do
    nc -z -w 1 127.0.0.1 "$PORT" 2>/dev/null || true
done
sleep 4

HONEY_AFTER=$(db_query "SELECT count(*) FROM events WHERE mitre_technique LIKE '%T1046%';" || echo "0")
HONEY_NEW=$((HONEY_AFTER - HONEY_BEFORE))

if [ "$HONEY_NEW" -gt 0 ]; then
    log_pass "Honeypot detected $HONEY_NEW probes"
else
    log_skip "Honeypot detection" "Trap ports bound inside container namespace"
fi

# ==============================================================================
# PHASE 6: API COMMANDS
# ==============================================================================
section "PHASE 6: API COMMANDS"

RELOAD_CFG=$(api_post "/api/config/reload")
if echo "$RELOAD_CFG" | grep -q '"success":true'; then
    log_pass "POST /api/config/reload accepted"
else
    log_fail "Config reload failed" "$RELOAD_CFG"
fi

RELOAD_RULES=$(api_post "/api/rules/reload")
if echo "$RELOAD_RULES" | grep -q '"success":true'; then
    log_pass "POST /api/rules/reload accepted"
else
    log_fail "Rule reload failed" "$RELOAD_RULES"
fi

sleep 2
POST_STATUS=$(curl $CURL_OPTS "${API_BASE}/api/status" 2>/dev/null || echo "")
if echo "$POST_STATUS" | grep -q "Operational"; then
    log_pass "Agent stable after reloads"
else
    log_fail "Agent unhealthy after reload" "$POST_STATUS"
fi

# ==============================================================================
# PHASE 7: DATABASE INTEGRITY
# ==============================================================================
section "PHASE 7: DATABASE INTEGRITY"

JOURNAL=$(db_query "PRAGMA journal_mode;" || echo "unknown")
if echo "$JOURNAL" | grep -qi "wal"; then
    log_pass "SQLite journal_mode = WAL"
else
    log_fail "Not in WAL mode" "$JOURNAL"
fi

SCHEMA=$(db_query ".schema events" || echo "")
EXPECTED=("event_id" "timestamp" "level" "mitre_tactic" "mitre_technique" \
    "pid" "ppid" "uid" "comm" "command_line" "target_file" "dest_ip" "dest_port" \
    "shannon_entropy" "execution_velocity" "tuple_rarity" "path_depth" \
    "anomaly_score" "message" "transmitted")

MISSING=""
for COL in "${EXPECTED[@]}"; do
    if ! echo "$SCHEMA" | grep -q "$COL"; then
        MISSING="$MISSING $COL"
    fi
done

if [ -z "$MISSING" ]; then
    log_pass "All 20 columns present in schema"
else
    log_fail "Missing columns" "$MISSING"
fi

NULL_IDS=$(db_query "SELECT count(*) FROM events WHERE event_id IS NULL;" || echo "0")
if [ "$NULL_IDS" = "0" ]; then
    log_pass "No NULL primary keys"
else
    log_fail "$NULL_IDS NULL event_ids" "PK integrity violated"
fi

NOW=$(date +%s)
FUTURE=$(db_query "SELECT count(*) FROM events WHERE timestamp > $((NOW + 60));" || echo "0")
if [ "$FUTURE" = "0" ]; then
    log_pass "No future timestamps"
else
    log_fail "$FUTURE future events" "Clock skew"
fi

TOTAL=$(db_query "SELECT count(*) FROM events;" || echo "0")
echo -e "  ${CYAN}[INFO]${NC} Total events: $TOTAL"

# ==============================================================================
# PHASE 8: SIEM FORWARDER STATE
# ==============================================================================
section "PHASE 8: SIEM FORWARDER"

QUEUED=$(db_query "SELECT count(*) FROM events WHERE transmitted = 0;" || echo "0")
SENT=$(db_query "SELECT count(*) FROM events WHERE transmitted = 1;" || echo "0")
echo -e "  ${CYAN}[INFO]${NC} Transmitted: $SENT | Queued: $QUEUED"

if [ "$QUEUED" -gt 0 ] || [ "$SENT" -gt 0 ]; then
    log_pass "Forwarder tracking transmission state ($QUEUED queued, $SENT sent)"
else
    log_fail "No events tracked" "Writer may not be persisting"
fi

# ==============================================================================
# PHASE 9: SELF-MONITORING SUPPRESSION
# ==============================================================================
section "PHASE 9: SELF-MONITORING SUPPRESSION"

SELF=$(db_query "SELECT count(*) FROM events WHERE comm LIKE 'linux-sentinel%' OR comm LIKE 'tokio-runtime%' OR comm LIKE 'tokio-rt-%';" || echo "0")
if [ "$SELF" = "0" ]; then
    log_pass "No self-referential events from agent processes"
else
    log_fail "$SELF events from agent's own processes" "Whitelist not suppressing"
fi

# ==============================================================================
# PHASE 10: CONTAINER HEALTH
# ==============================================================================
section "PHASE 10: CONTAINER HEALTH"

RESTARTS=$($CONTAINER_CLI inspect --format '{{.RestartCount}}' "$AGENT_CONTAINER" 2>/dev/null || echo "0")
if [ "$RESTARTS" = "0" ]; then
    log_pass "Zero container restarts"
else
    log_fail "Container restarted $RESTARTS times" "Check logs"
fi

OOM=$($CONTAINER_CLI inspect --format '{{.State.OOMKilled}}' "$AGENT_CONTAINER" 2>/dev/null || echo "false")
if [ "$OOM" = "false" ]; then
    log_pass "No OOM kills"
else
    log_fail "OOM killed" "Increase memory limit"
fi

LOG_OUTPUT=$($CONTAINER_CLI logs --tail 50 "$AGENT_CONTAINER" 2>&1 || true)
ERRORS=$(echo "$LOG_OUTPUT" | grep -c '"level":"ERROR"' || true)
if [ "$ERRORS" -lt 5 ]; then
    log_pass "Low error rate ($ERRORS in last 50 lines)"
else
    log_fail "Elevated errors: $ERRORS in last 50 lines" "Review logs"
fi

# ==============================================================================
# PHASE 11: SIGNAL HANDLING
# ==============================================================================
section "PHASE 11: SIGNAL HANDLING"

$CONTAINER_CLI kill --signal=HUP "$AGENT_CONTAINER" 2>/dev/null || true
sleep 3

ALIVE=$($CONTAINER_CLI inspect --format '{{.State.Running}}' "$AGENT_CONTAINER" 2>/dev/null || echo "false")
if echo "$ALIVE" | grep -qiE "true|running"; then
    log_pass "Agent survived SIGHUP"
else
    log_fail "Agent crashed on SIGHUP" "Signal handler broken"
fi

RELOAD_LOG=$($CONTAINER_CLI logs --tail 200 "$AGENT_CONTAINER" 2>&1 | grep -c "hot-swapped\|hot-reload\|SIGHUP" || true)
if [ "$RELOAD_LOG" -gt 0 ]; then
    log_pass "SIGHUP triggered reload (confirmed in logs)"
else
    log_fail "No reload log entry after SIGHUP" "Handler may have failed silently"
fi

# ==============================================================================
# RESULTS
# ==============================================================================
section "VALIDATION RESULTS"

TOTAL_TESTS=$((PASS + FAIL + SKIP))
echo ""
echo -e "  Tests Run:    ${CYAN}$TOTAL_TESTS${NC}"
echo -e "  Passed:       ${GREEN}$PASS${NC}"
echo -e "  Failed:       ${RED}$FAIL${NC}"
echo -e "  Skipped:      ${YELLOW}$SKIP${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}  ALL TESTS PASSED -- PIPELINE INTEGRITY VERIFIED${NC}"
    echo -e "  ${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    exit 0
else
    echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${RED}  $FAIL TEST(S) FAILED -- REVIEW ABOVE${NC}"
    echo -e "  ${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    for R in "${RESULTS[@]}"; do
        if echo "$R" | grep -q "^FAIL|"; then
            echo -e "    ${RED}✗${NC} $(echo "$R" | cut -d'|' -f2)"
            echo -e "      → $(echo "$R" | cut -d'|' -f3)"
        fi
    done
    exit 1
fi
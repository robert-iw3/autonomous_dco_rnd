#!/usr/bin/env bash
# =============================================================================
# run_tests.sh -- Nexus modular test runner
#
# Each section maps to a lightweight Dockerfile.* that builds only the deps
# and source needed for that area of the codebase.  Change-detection maps
# modified files to affected sections so only relevant containers run.
#
# Usage:
#   ./run_tests.sh                              # auto-detect changes vs HEAD~1
#   ./run_tests.sh --full                       # run all sections
#   ./run_tests.sh --section offline            # run one section by name
#   ./run_tests.sh --section "mlops services"   # run multiple sections
#   ./run_tests.sh --base main                  # diff against a specific ref
#   ./run_tests.sh --rebuild                    # bypass docker layer cache
#   ./run_tests.sh --parallel                   # run sections concurrently
#   ./run_tests.sh --live                       # stream container output live (see test-by-test progress)
#   ./run_tests.sh --status                     # show XML summary + running containers, no test run
#   ./run_tests.sh --list                       # show sections and their triggers
#
# Exit code: 0 = all sections passed, 1 = one or more failed
# =============================================================================

set -euo pipefail

# Path resolution
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"   # autonomous_dco_rnd/
REPO_ROOT="$(cd "$PROJECT_ROOT/.." && pwd)"

# (disabled when not a tty)
if [ -t 1 ]; then
    RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
    CYAN='\033[0;36m' BOLD='\033[1m' RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

# -- Section registry ---------------------------------------------------------
# Format: name|dockerfile|description
SECTIONS=(
    "offline|Dockerfile.offline|107 fast offline tests (turbovec + rsi_loop)"
    "sensors|Dockerfile.sensors|Sensor schema, Parquet, vector-dim, HMAC tests"
    "mlops|Dockerfile.mlops|MLOps pipeline: data flow, dedup, track6, ti_ingest, eval_minilab"
    "analytics|Dockerfile.analytics|Analytics hunter, agentic swarm, redteam bypass"
    "governance|Dockerfile.governance|NIST AI 600-1 control suite + GRC manifest/evidence/wiring"
    "memory|Dockerfile.memory|worker_memory — memory-forensics bridge to the agentic stack"
    "bench|Dockerfile.bench|WS-A benchmark harness — registry + runner + RSI score-file contract"
    "services|Dockerfile.services|Worker + infra source-contract tests (pure source reads)"
    "pipeline|Dockerfile.pipeline|Phase1/2/3 pipeline, guardrails, mlops_serving, mlops_train"
    "detchamber|Dockerfile.detchamber|Det Chamber engine + acquisition + intake/detonation lifecycle"
    "siem|Dockerfile.siemfed|SIEM-federated investigation mock E2E (CIM/ECS fanout + swarm pivot + counterpart disproof)"
    "siemlab|Dockerfile.siemlab|WS-J standalone agentic SIEM analysis — runner + coverage + Track 10 corpus"
    "grc|Dockerfile.grc|GRC-as-Code continuous assessment — binds controls to real JUnit, scores posture, gates on posture_baseline.json (runs LAST, consumes all sections)"
)

# The grc section consumes every other section's JUnit, so it must run AFTER them
# (last in sequential order; deferred past the parallel batch in --parallel mode).
GRC_SECTION="grc"

# -- Change → section trigger map ---------------------------------------------
# Each entry: "regex_pattern:section1 section2 ..."
# If a changed file path matches the regex, those sections are queued.
TRIGGERS=(
    "mlops/scripts/corpus_utils|mlops/scripts/08_rsi|mlops/scripts/01_spool|mlops/scripts/05_critic:offline mlops pipeline"
    "mlops/scripts/:mlops pipeline offline"
    "mlops/config/:pipeline"
    "mlops/data/:mlops"
    "analytics/llm_hunter/agents/controls|analytics/llm_hunter/agents/verdict_ledger|analytics/llm_hunter/agents/energy_accounting|analytics/llm_hunter/agents/active_learning|analytics/llm_hunter/agents/calibration_ledger|analytics/llm_hunter/agents/bias_audit|analytics/llm_hunter/agents/endpoint_abuse_monitor|analytics/llm_hunter/agents/scheduled_audits:governance"
    "analytics/llm_hunter/tools/siem|analytics/llm_hunter/agents/review_board:analytics siem governance"
    "analytics/llm_hunter/:analytics services governance"
    "analytics/:analytics"
    "docs/governance/grc_lib|docs/governance/grc_assess|docs/governance/controls_manifest|docs/governance/posture_baseline|tests/lab_grc_assessment:grc"
    "docs/governance/:governance grc"
    "services/worker_memory/:memory"
    "tests/lab_memory_forensics:memory"
    "mlops/benchmarks/|mlops/scripts/09_benchmark_runner|mlops/scripts/10_freeze_replay_case|mlops/scripts/12_eval_qa|tests/lab_benchmarks:bench"
    "mlops/scripts/08_rsi_loop:bench pipeline"
    "services/model_steward/|mlops/scripts/13_publish_model:pipeline services"
    "analytics/llm_hunter/siem_analysis/|tests/lab_agentic_siem|detection_training/|mlops/scripts/siem_analysis_track:siemlab"
    "middleware/config/:siem services"
    "det_chamber/:detchamber"
    "services/worker_ti_ingest/:mlops"
    "services/config/nexus:sensors"
    "services/:services"
    "infrastructure/:services"
    "orchestration/:services"
    "operations/:services"
    "middleware/:services"
    "libs/:services"
    "windows/sysmon_sensor|windows/trellix|windows/prototypes/c2_sensor:sensors pipeline"
    "windows/:pipeline sensors"
    "tests/sensors/:sensors"
    "tests/test_turbovec|tests/lab_mlops_train/test_rsi:offline mlops"
    "tests/test_data_flow|tests/test_track6|tests/test_s3_query|tests/test_cross_source|tests/test_worker_ti|tests/mlops_eval:mlops"
    "tests/test_phase:pipeline"
    "tests/test_worker_contracts|tests/lab_worker_rules|tests/lab_infra|tests/lab_operations|tests/lab_orchestration:services"
    "tests/lab_analytics_hunter|tests/lab_agentic_swarm|tests/lab_redteam:analytics"
    "tests/lab_governance:governance"
    "tests/lab_det_chamber:detchamber"
    "tests/lab_siem_federation:siem"
    "tests/lab_mlops_serving|tests/lab_mlops_train:pipeline"
    "tests/sensors/:sensors"
)

# -- Reports directory --------------------
REPORTS_DIR="$SCRIPT_DIR/reports"
mkdir -p "$REPORTS_DIR"

# -- Defaults ------------------------------------------------------------------
MODE="auto"          # auto | full | explicit | status
EXPLICIT_SECTIONS="" # when --section is used
BASE_REF="HEAD~1"
REBUILD=0
PARALLEL=0
LIVE=0               # stream container output live instead of capturing

# -- XML report summary --------------------------------------------------------
show_xml_summary() {
    local sections_list=("$@")
    [[ ${#sections_list[@]} -eq 0 ]] && for e in "${SECTIONS[@]}"; do sections_list+=("$(section_name "$e")"); done
    echo ""
    echo -e "${BOLD}  XML Report Summary${RESET}  ($(date '+%Y-%m-%d %H:%M'))"
    printf "  %-12s  %6s  %6s  %6s  %6s  %s\n" "SECTION" "TESTS" "PASS" "FAIL" "SKIP" "STATUS"
    printf "  %s\n" "$(printf '%0.s-' {1..60})"
    local all_clean=1
    for sec in "${sections_list[@]}"; do
        local xml="${REPORTS_DIR}/${sec}.xml"
        if [[ ! -f "$xml" ]]; then
            printf "  ${YELLOW}%-12s${RESET}  %6s\n" "$sec" "(no report)"
            all_clean=0
            continue
        fi
        local result
        result=$(python3 -c "
import xml.etree.ElementTree as ET, sys
try:
    t = ET.parse('$xml')
    r = t.getroot()
    s = next(r.iter('testsuite'), r)
    tot=int(s.get('tests',0)); f=int(s.get('failures',0)); e=int(s.get('errors',0)); sk=int(s.get('skipped',0))
    p=tot-f-e-sk
    print(tot,p,f+e,sk)
except Exception as ex:
    print('? ? ? ?')
" 2>/dev/null)
        local tot p fe sk
        read -r tot p fe sk <<< "$result"
        local color="$GREEN" label="PASS"
        [[ "$fe" != "0" ]] && { color="$RED"; label="FAIL"; all_clean=0; }
        printf "  ${color}%-12s${RESET}  %6s  %6s  %6s  %6s  ${color}%s${RESET}\n" \
            "$sec" "$tot" "$p" "$fe" "$sk" "$label"
    done
    echo ""
    if [[ $all_clean -eq 1 ]]; then
        echo -e "  ${GREEN}${BOLD}All sections clean.${RESET}"
    fi
}

# -- Argument parsing ----------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)         MODE="full";         shift ;;
        --section)      MODE="explicit";     EXPLICIT_SECTIONS="$2"; shift 2 ;;
        --base)         BASE_REF="$2";       shift 2 ;;
        --rebuild)      REBUILD=1;           shift ;;
        --parallel)     PARALLEL=1;          shift ;;
        --live)         LIVE=1;              shift ;;
        --status)       MODE="status";       shift ;;
        --list)
            echo ""
            printf "${BOLD}%-12s  %-28s  %s${RESET}\n" "SECTION" "DOCKERFILE" "DESCRIPTION"
            printf '%0.s-' {1..80}; echo ""
            for entry in "${SECTIONS[@]}"; do
                IFS='|' read -r name dfile desc <<< "$entry"
                printf "%-12s  %-28s  %s\n" "$name" "$dfile" "$desc"
            done
            echo ""
            exit 0
            ;;
        -h|--help)
            sed -n '/^# Usage:/,/^# ====/p' "$0" | grep "^#" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# -- Helpers -------------------------------------------------------------------
log()  { echo -e "${CYAN}[run_tests]${RESET} $*"; }
pass() { echo -e "${GREEN}[PASS]${RESET} $*"; }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }

section_name()  { IFS='|' read -r n _ _ <<< "$1"; echo "$n"; }
section_file()  { IFS='|' read -r _ f _ <<< "$1"; echo "$f"; }
section_desc()  { IFS='|' read -r _ _ d <<< "$1"; echo "$d"; }

# -- Detect changed files ------------------------------------------------------
get_changed_files() {
    cd "$REPO_ROOT"
    if git rev-parse --verify "$BASE_REF" &>/dev/null; then
        git diff --name-only "$BASE_REF" HEAD 2>/dev/null || true
    fi
    # Also include uncommitted changes
    git diff --name-only HEAD 2>/dev/null || true
    git diff --name-only 2>/dev/null || true
}

# -- Map changed files → sections ---------------------------------------------
detect_sections() {
    local changed="$1"
    local queued=""

    for trigger_entry in "${TRIGGERS[@]}"; do
        local pattern sections_for_pattern
        pattern="${trigger_entry%%:*}"
        sections_for_pattern="${trigger_entry##*:}"

        if echo "$changed" | grep -qE "$pattern"; then
            queued="$queued $sections_for_pattern"
        fi
    done

    # Deduplicate, preserve order
    echo "$queued" | tr ' ' '\n' | awk '!seen[$0]++' | grep -v '^$' | tr '\n' ' '
}

# -- Docker build + run for a single section (ephemeral: rmi after run) --------
run_section() {
    local name="$1"
    local dockerfile="$2"
    local image="nexus-test-${name}"
    local report_xml="${REPORTS_DIR}/${name}.xml"
    local log_file
    log_file="$(mktemp /tmp/nexus-test-${name}-XXXXXX.log)"

    # Remove stale report from a previous run
    rm -f "$report_xml"

    local build_args=("-f" "autonomous_dco_rnd/tests/${dockerfile}" "-t" "${image}")
    [[ $REBUILD -eq 1 ]] && build_args+=("--no-cache")

    echo -e "${CYAN}[${name}]${RESET} building ${dockerfile}..."
    if ! docker build "${build_args[@]}" . > "$log_file" 2>&1; then
        fail "[${name}] BUILD FAILED -- see ${log_file}"
        docker rmi "${image}" &>/dev/null || true
        return 1
    fi

    echo -e "${CYAN}[${name}]${RESET} running tests..."
    local start_ts
    start_ts=$(date +%s)

    local exit_code=0
    if [[ $LIVE -eq 1 ]]; then
        docker run --rm \
            -e PYTHONHASHSEED=0 \
            -v "${REPORTS_DIR}:/reports" \
            "${image}" \
            2>&1 | tee "$log_file"
        exit_code=${PIPESTATUS[0]}
    else
        docker run --rm \
            -e PYTHONHASHSEED=0 \
            -v "${REPORTS_DIR}:/reports" \
            "${image}" \
            >> "$log_file" 2>&1 || exit_code=$?
    fi

    local elapsed=$(( $(date +%s) - start_ts ))

    # Ephemeral: delete image regardless of test outcome
    docker rmi "${image}" >> "$log_file" 2>&1 || true

    # Validate report was written
    local report_status
    if [[ -f "$report_xml" ]]; then
        report_status="report → tests/reports/${name}.xml"
    else
        report_status="WARNING: report not written to /reports/${name}.xml"
    fi

    if [[ $exit_code -eq 0 ]]; then
        local summary
        summary=$(grep -E "passed|failed|error" "$log_file" | tail -1 || echo "no summary")
        pass "[${name}] ${summary}  (${elapsed}s)  ${report_status}"
        rm -f "$log_file"
        return 0
    else
        fail "[${name}] TESTS FAILED (exit ${exit_code}, ${elapsed}s)  ${report_status} -- log: ${log_file}"
        echo "--- last output ---"
        tail -30 "$log_file" | sed "s/^/  /"
        echo "-------------------"
        return 1
    fi
}

# -- Main ----------------------------------------------------------------------
cd "$REPO_ROOT"

# -- Status-only mode: parse existing reports and exit -------------------------
if [[ "$MODE" == "status" ]]; then
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  Nexus Test Status${RESET}"
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"

    # Show any running containers
    local_running=$(docker ps 2>/dev/null | grep "nexus-test-" || true)
    if [[ -n "$local_running" ]]; then
        echo ""
        echo -e "${CYAN}  Running containers:${RESET}"
        echo "$local_running" | awk '{print "    " $1, $2, $NF}' | sed 's/.*\(Up.*\)/  \1/'
        docker ps 2>/dev/null | grep "nexus-test-" | awk '{print "    "$NF" ("$7" "$8")"}'
    else
        echo -e "  ${YELLOW}No test containers currently running.${RESET}"
    fi

    show_xml_summary
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    exit 0
fi

# Determine which sections to run
SECTIONS_TO_RUN=()

case "$MODE" in
    full)
        for entry in "${SECTIONS[@]}"; do
            SECTIONS_TO_RUN+=("$(section_name "$entry")")
        done
        ;;
    explicit)
        IFS=' ' read -ra SECTIONS_TO_RUN <<< "$EXPLICIT_SECTIONS"
        ;;
    auto)
        CHANGED=$(get_changed_files | sort -u)
        if [[ -z "$CHANGED" ]]; then
            warn "No changed files detected vs ${BASE_REF}. Use --full to run everything."
            exit 0
        fi
        log "Changed files (vs ${BASE_REF}):"
        echo "$CHANGED" | sed 's/^/  /'
        DETECTED=$(detect_sections "$CHANGED")
        if [[ -z "${DETECTED// }" ]]; then
            warn "No test sections triggered by these changes. Use --full to run everything."
            exit 0
        fi
        IFS=' ' read -ra SECTIONS_TO_RUN <<< "$DETECTED"
        ;;
esac

# Continuous assessment: whenever any section is queued in change-detect mode, the
# GRC gate re-runs too (a change to a control-backing file can flip proven posture).
if [[ "$MODE" == "auto" && ${#SECTIONS_TO_RUN[@]} -gt 0 ]]; then
    SECTIONS_TO_RUN+=("$GRC_SECTION")
fi

# The grc section consumes every other section's JUnit → force it to run LAST
# (and de-duplicate if it was queued more than once).
if [[ ${#SECTIONS_TO_RUN[@]} -gt 0 ]]; then
    _reordered=(); _has_grc=0
    for s in "${SECTIONS_TO_RUN[@]}"; do
        if [[ "$s" == "$GRC_SECTION" ]]; then _has_grc=1; else _reordered+=("$s"); fi
    done
    [[ $_has_grc -eq 1 ]] && _reordered+=("$GRC_SECTION")
    SECTIONS_TO_RUN=("${_reordered[@]}")
fi

# Print header
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Nexus Test Runner${RESET}   mode=${MODE}   sections: ${SECTIONS_TO_RUN[*]}"
echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo ""

PASS_COUNT=0
FAIL_COUNT=0
FAILED_SECTIONS=()

if [[ $PARALLEL -eq 1 ]]; then
    # Parallel: launch all sections concurrently EXCEPT grc, which must consume
    # their finished JUnit — it runs sequentially after the batch drains.
    declare -A PIDS
    declare -A PIPE_FILES
    PARALLEL_BATCH=(); RUN_GRC_AFTER=0
    for sec in "${SECTIONS_TO_RUN[@]}"; do
        if [[ "$sec" == "$GRC_SECTION" ]]; then RUN_GRC_AFTER=1; else PARALLEL_BATCH+=("$sec"); fi
    done
    for sec in "${PARALLEL_BATCH[@]}"; do
        dockerfile=""
        for entry in "${SECTIONS[@]}"; do
            [[ "$(section_name "$entry")" == "$sec" ]] && dockerfile="$(section_file "$entry")" && break
        done
        if [[ -z "$dockerfile" ]]; then
            warn "Unknown section '${sec}' -- skipping"
            continue
        fi
        pipe_file=$(mktemp /tmp/nexus-pipe-${sec}-XXXXXX)
        run_section "$sec" "$dockerfile" > "$pipe_file" 2>&1 &
        PIDS[$sec]=$!
        PIPE_FILES[$sec]="$pipe_file"
    done

    for sec in "${!PIDS[@]}"; do
        wait "${PIDS[$sec]}" && rc=0 || rc=$?
        cat "${PIPE_FILES[$sec]}"
        rm -f "${PIPE_FILES[$sec]}"
        if [[ $rc -eq 0 ]]; then
            (( PASS_COUNT++ )) || true
        else
            (( FAIL_COUNT++ )) || true
            FAILED_SECTIONS+=("$sec")
        fi
    done

    # grc runs after the parallel batch drains (it reads their JUnit)
    if [[ $RUN_GRC_AFTER -eq 1 ]]; then
        grc_dockerfile=""
        for entry in "${SECTIONS[@]}"; do
            [[ "$(section_name "$entry")" == "$GRC_SECTION" ]] && grc_dockerfile="$(section_file "$entry")" && break
        done
        echo ""
        if run_section "$GRC_SECTION" "$grc_dockerfile"; then
            (( PASS_COUNT++ )) || true
        else
            (( FAIL_COUNT++ )) || true
            FAILED_SECTIONS+=("$GRC_SECTION")
        fi
    fi
else
    # Sequential
    for sec in "${SECTIONS_TO_RUN[@]}"; do
        dockerfile=""
        for entry in "${SECTIONS[@]}"; do
            [[ "$(section_name "$entry")" == "$sec" ]] && dockerfile="$(section_file "$entry")" && break
        done
        if [[ -z "$dockerfile" ]]; then
            warn "Unknown section '${sec}' -- skipping"
            continue
        fi
        echo ""
        if run_section "$sec" "$dockerfile"; then
            (( PASS_COUNT++ )) || true
        else
            (( FAIL_COUNT++ )) || true
            FAILED_SECTIONS+=("$sec")
        fi
    done
fi

# Summary
TOTAL=$(( PASS_COUNT + FAIL_COUNT ))
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${BOLD}  ${GREEN}RESULT: ${PASS_COUNT}/${TOTAL} sections passed${RESET}"
else
    echo -e "${BOLD}  ${RED}RESULT: ${PASS_COUNT}/${TOTAL} passed -- FAILED: ${FAILED_SECTIONS[*]}${RESET}"
fi

# List generated reports
echo ""
echo -e "${BOLD}  Reports written to tests/reports/${RESET}"
for sec in "${SECTIONS_TO_RUN[@]}"; do
    local_report="${REPORTS_DIR}/${sec}.xml"
    if [[ -f "$local_report" ]]; then
        size=$(wc -c < "$local_report")
        echo -e "    ${GREEN}✓${RESET}  ${sec}.xml  (${size} bytes)"
    else
        echo -e "    ${RED}✗${RESET}  ${sec}.xml  (not found)"
    fi
done

echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo ""

# XML summary for all sections that were run
show_xml_summary "${SECTIONS_TO_RUN[@]}"

echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo ""

[[ $FAIL_COUNT -eq 0 ]]
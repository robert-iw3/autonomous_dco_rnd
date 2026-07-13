"""
Lab 10b: Query Cookbook validation -- the swarm's starting-point DuckDB playbook.

The cookbook (analytics/llm_hunter/tools/query_cookbook.py) seeds every expert
with concrete, schema-correct DuckDB query patterns. A wrong column name or an
unparseable template silently degrades every investigation that uses it, so each
pattern is validated three ways with no live infra:

  1. EXECUTES + COLUMNS EXIST -- the filled SQL runs against a synthetic in-memory
     table built from exactly the columns in SENSOR_SCHEMA[sensor]. A reference to
     a column the sensor does not emit raises a DuckDB binder error -> fail. This
     is the cookbook analogue of test_track6_dryrun for the live swarm.
  2. GUARDRAIL-SAFE -- every pattern passes the DuckDBQueryTool _FORBIDDEN and
     _LOCAL_FS regexes (read-only, S3-only) and is bounded (DESCRIBE or LIMIT).
  3. CONTRACT -- S3_PATH and SENSOR_SCHEMA cover every sensor; render_playbook
     resolves {src} to the real S3 glob for the experts.

Run:
    pytest tests/lab_analytics_hunter/test_query_cookbook.py -v
"""

import ast
import re
import sys
from pathlib import Path

import duckdb
import pandas as pd
import pytest

HUNTER_DIR = Path(__file__).parent.parent.parent / "analytics/llm_hunter"
sys.path.insert(0, str(HUNTER_DIR))
sys.path.insert(0, str(HUNTER_DIR / "tools"))

# query_cookbook has no heavy deps (dataclasses/typing only), so it imports clean.
import query_cookbook as qc          # noqa: E402

ALL_SENSORS = sorted(qc.S3_PATH.keys())


# ── Guardrail regexes lifted from duckdb_query.py source (no import) ─────────
# Importing the live DuckDBQueryTool pulls the whole tools/ package (qdrant,
# redis, requests, langchain) which the test container omits. We extract the two
# guardrail patterns by parsing the source so the test still validates against
# the REAL regexes and fails if they drift.
def _extract_regex(var_name: str) -> "re.Pattern":
    src = (HUNTER_DIR / "tools" / "duckdb_query.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == var_name for t in node.targets
        ):
            # value is re.compile(<pattern str>, [flags]); adjacent string
            # literals are already merged into one constant by the parser.
            pattern = ast.literal_eval(node.value.args[0])
            return re.compile(pattern, re.IGNORECASE)
    raise AssertionError(f"{var_name} not found in duckdb_query.py")


_FORBIDDEN = _extract_regex("_FORBIDDEN")
_LOCAL_FS = _extract_regex("_LOCAL_FS")

# ── Type-correct placeholder literals (numeric slots stay numeric in SQL) ─────
_PLACEHOLDERS = {
    "ts_lo": "1717500000", "ts_hi": "1717600000",
    "pid": "1234", "min_score": "75", "event_ids": "1, 3, 22",
    "comm": "bash", "sensor_id": "WIN-TEST-01", "image_loaded": "driver.sys",
    "dst_ip": "10.10.0.9", "host": "host-01", "community_id": "1:abc=",
    "src_ip": "10.0.0.5", "tls_ja3": "abc123def", "dt": "2026-06-09",
    "hour": "14", "event_type": "entraid_signin", "process_hash": "arn:aws:iam::1:user/x",
}

# Columns that must be numeric/boolean for comparisons & aggregations to bind.
_FLOAT_COLS = {
    "timestamp", "timestamp_start", "timestamp_end", "session_duration_ms",
    "score", "anomaly_score", "parent_child_score", "integrity_score",
    "command_entropy", "shannon_entropy", "payload_entropy", "avg_entropy",
    "max_velocity", "execution_velocity", "tuple_rarity", "path_depth",
    "cv", "interval", "outbound_ratio", "packet_size_mean", "packet_size_min",
    "packet_size_max", "packet_size_std", "cmd_entropy", "entropy",
    "byte_ratio", "avg_inter_arrival", "variance_inter_arrival",
    "ratio_small_packets", "ratio_large_packets", "cert_valid_days",
    "packet_count", "bytes_src", "bytes_dst", "data_bytes_src", "data_bytes_dst",
    "packets_src", "packets_dst", "severity",
}
_INT_COLS = {
    "pid", "ppid", "tid", "uid", "ProcessId", "ParentProcessId", "parent_pid",
    "PID", "TID", "dst_port", "dest_port", "src_port", "DestinationPort", "port",
    "Port", "sysmon_event_id", "alert_sid", "flow_pkts_toserver",
    "flow_pkts_toclient", "flow_bytes_toserver", "flow_bytes_toclient",
    "http_status", "http_status_code", "dns_rcode", "event_count",
    "tcp_syn", "tcp_rst", "tcp_fin",
}
_BOOL_COLS = {"is_internal_dst", "cert_self_signed", "Signed", "quarantine_flag"}


def _synthetic_value(col: str):
    if col in _BOOL_COLS:
        return True
    if col in _FLOAT_COLS:
        return 1.0
    if col in _INT_COLS:
        return 1
    return "x"


def _make_view(con, sensor: str):
    cols = sorted(qc.SENSOR_SCHEMA[sensor])
    row = {c: _synthetic_value(c) for c in cols}
    df = pd.DataFrame([row])
    con.register("cookbook_src", df)


def _fill(sql: str) -> str:
    out = sql.replace("{src}", "cookbook_src")
    for key, val in _PLACEHOLDERS.items():
        out = out.replace("{" + key + "}", val)
    return out


# ── 1. Execution + column existence (one case per pattern x sensor) ──────────
_CASES = [(p, s) for p in qc.all_patterns() for s in p.sensors]


@pytest.mark.parametrize("pattern,sensor", _CASES,
                         ids=[f"{p.id}-{s}" for p, s in _CASES])
def test_pattern_executes_against_sensor_schema(pattern, sensor):
    con = duckdb.connect(":memory:")
    try:
        _make_view(con, sensor)
        filled = _fill(pattern.sql)
        assert "{" not in filled, f"unfilled placeholder in {pattern.id}: {filled}"
        # Executes without a binder error => every referenced column exists in the
        # sensor's production schema and the SQL is well-formed.
        con.execute(filled).fetchall()
    finally:
        con.close()


# ── 2. Guardrail safety (must survive the live DuckDBQueryTool gates) ─────────
@pytest.mark.parametrize("pattern", qc.all_patterns(), ids=[p.id for p in qc.all_patterns()])
def test_pattern_is_guardrail_safe(pattern):
    sql = pattern.sql
    assert not _FORBIDDEN.search(sql), \
        f"{pattern.id} contains a forbidden statement keyword"
    assert not _LOCAL_FS.search(sql), \
        f"{pattern.id} references a local-filesystem reader"


@pytest.mark.parametrize("pattern", qc.all_patterns(), ids=[p.id for p in qc.all_patterns()])
def test_pattern_is_bounded(pattern):
    sql = pattern.sql.strip().upper()
    if sql.startswith("DESCRIBE"):
        return  # DESCRIBE is schema-only, exempt from LIMIT
    assert re.search(r"\bLIMIT\b", sql), f"{pattern.id} has no LIMIT and is not a DESCRIBE"


@pytest.mark.parametrize("pattern", qc.all_patterns(), ids=[p.id for p in qc.all_patterns()])
def test_pattern_is_read_only(pattern):
    upper = pattern.sql.strip().upper()
    assert upper.startswith("SELECT") or upper.startswith("DESCRIBE"), \
        f"{pattern.id} is neither SELECT nor DESCRIBE"


# ── 3. Coverage & metadata contracts ─────────────────────────────────────────
def test_every_sensor_has_path_and_schema():
    assert set(qc.S3_PATH) == set(qc.SENSOR_SCHEMA), "S3_PATH and SENSOR_SCHEMA disagree on sensors"


def test_every_pattern_targets_known_sensors():
    for p in qc.all_patterns():
        assert p.sensors, f"{p.id} targets no sensors"
        for s in p.sensors:
            assert s in qc.SENSOR_SCHEMA, f"{p.id} targets unknown sensor {s}"


def test_every_pattern_has_known_phase():
    for p in qc.all_patterns():
        assert p.phase in qc.PHASE_ORDER, f"{p.id} has unknown phase {p.phase}"


def test_pattern_ids_unique():
    ids = [p.id for p in qc.all_patterns()]
    assert len(ids) == len(set(ids)), "duplicate pattern ids in cookbook"


def test_every_sensor_has_at_least_one_pattern():
    # Generic patterns (introspect) cover every sensor, so this also guards that
    # the generic set is wired to all paths.
    for sensor in ALL_SENSORS:
        assert qc.patterns_for(sensor), f"no cookbook pattern for {sensor}"


# ── 4. Playbook rendering (what the experts actually receive) ────────────────
@pytest.mark.parametrize("sensors", [
    ["linux_sentinel", "sysmon_sensor", "windows_deepsensor", "macos_sensor", "trellix_ens"],
    ["linux_c2", "windows_c2", "suricata_eve"],
    ["aws_cloudtrail", "azure_entraid", "gcp_audit", "aws_guardduty", "azure_nsg"],
    ["network_tap"],
])
def test_render_playbook_resolves_src_to_s3(sensors):
    pb = qc.render_playbook(sensors)
    assert "QUERY PLAYBOOK" in pb
    # Every rendered SQL FROM line must point at cold storage, never a raw {src}.
    for line in pb.splitlines():
        if "FROM '" in line:
            assert "s3://nexus-cold-storage" in line, f"unresolved FROM: {line}"
            assert "{src}" not in line, f"unresolved placeholder: {line}"


def test_render_playbook_orders_by_phase():
    pb = qc.render_playbook(["linux_sentinel", "sysmon_sensor"])
    seen = [ph for ph in qc.PHASE_ORDER if f"-- {ph.upper()} --" in pb]
    # phases that appear must appear in canonical order
    positions = [pb.index(f"-- {ph.upper()} --") for ph in seen]
    assert positions == sorted(positions), "playbook phases out of order"


def test_introspect_pattern_first_for_every_expert():
    # The DESCRIBE-first discipline must be present for every expert grouping.
    for sensors in (["linux_sentinel"], ["linux_c2"], ["aws_cloudtrail"], ["network_tap"]):
        pb = qc.render_playbook(sensors)
        assert "INTROSPECT" in pb and "DESCRIBE" in pb

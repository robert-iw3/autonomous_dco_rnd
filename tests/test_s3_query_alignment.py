"""
test_s3_query_alignment.py -- Production Track 6 S3 query column name validation.

Run:
    pytest tests/test_s3_query_alignment.py -v
    pytest tests/test_s3_query_alignment.py -v --tb=short 2>&1 | head -80
"""

import json
import re
import pytest
from pathlib import Path

STAGING_DIR = Path(__file__).parent.parent / "mlops" / "data" / "staging"

# ── Exact column names that exist in each sensor's Parquet ────────────────────
# Source:
#   sysmon_sensor:      windows/sysmon_sensor/schema.py SCHEMA
#   linux_sentinel:     linux/sentinel/src/siem/parquet_transmitter.rs
#   network_tap:        services/config/nexus.toml [schema_mappings.network_tap]
#   windows_deepsensor: services/config/nexus.toml [schema_mappings.windows_deepsensor]
#   linux_c2/windows_c2: services/config/nexus.toml [schema_mappings.linux_c2/windows_c2]
#   azure_entraid:      Azure Monitor / Entra ID audit log schema (CLOUD_COLS)
#   aws_cloudtrail:     AWS CloudTrail management event schema (CLOUD_COLS)

SENSOR_COLUMNS = {
    "sysmon_sensor": {
        # Core
        "sensor_type", "sensor_id", "timestamp", "sysmon_event_id",
        # Event 1: Process Create
        "Image", "CommandLine", "ParentImage", "ParentCommandLine",
        "User", "IntegrityLevel", "ProcessId", "ParentProcessId",
        "Hashes", "CurrentDirectory", "RuleName",
        # Event 3: Network Connection
        "DestinationIp", "DestinationPort", "Protocol", "Initiated",
        # Event 6/7: Driver/Image Load
        "ImageLoaded", "Signed", "SignatureStatus", "SignatureIssuer",
        # Event 8: CreateRemoteThread
        "SourceImage", "TargetImage", "StartAddress", "StartModule",
        # Event 10: ProcessAccess
        "GrantedAccess",
        # Event 11/23/26: File Events
        "TargetFilename",
        # Event 12/13/14: Registry Events
        "TargetObject", "Details", "EventType_reg",
        # Event 17/18: Pipe Events
        "PipeName",
        # Event 22: DNS Query
        "QueryName", "QueryResults",
        # Event 25: Process Tampering
        "TamperingType",
        # windows_math 6D vector
        "command_entropy", "parent_child_score", "integrity_score",
        "anomaly_score", "grant_access_score", "driver_trust_score",
        "payload_raw",
    },

    "linux_sentinel": {
        "event_id", "endpoint_id", "timestamp", "level",
        "mitre_tactic", "mitre_technique",
        "pid", "ppid", "uid", "container_name",
        "comm", "command_line", "parent_comm", "user_name",
        "target_file", "dest_ip", "dest_port",
        # sentinel_math 5D
        "shannon_entropy", "execution_velocity", "tuple_rarity",
        "path_depth", "anomaly_score",
        "message", "in_memory_capture", "ml_vector", "payload_raw",
    },

    "network_tap": {
        "session_id", "timestamp_start", "sensor_name", "sensor_type",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol_name",
        "dns_query", "dns_status", "http_uri", "http_method", "http_useragent",
        "tls_ja3", "tls_ja3s", "tls_version",
        "cert_cn", "cert_issuer_cn", "cert_self_signed", "cert_valid_days",
        "dst_geo_country", "dst_asn_org", "hostname", "is_internal_dst", "port_class",
        # network_tap 8D vector
        "byte_ratio", "avg_inter_arrival", "variance_inter_arrival",
        "ratio_small_packets", "ratio_large_packets",
        "payload_entropy", "session_duration_ms", "packets_src",
        "payload_raw",
    },

    "windows_deepsensor": {
        "event_id", "timestamp", "category", "event_type",
        "pid", "parent_pid", "tid", "path", "parent_image",
        "command_line", "event_user", "destination_ip", "port",
        "signature_name", "tactic", "technique", "severity",
        # deepsensor_math 4D
        "score", "avg_entropy", "max_velocity", "event_count",
    },

    # linux_c2 / windows_c2 share c2_math fields
    "linux_c2": {
        "id", "event_id", "timestamp", "sensor_id", "host", "user", "host_ip",
        "process_name", "pid", "uid", "process_hash", "event_type",
        "dst_ip", "dst_port", "packet_size_min", "packet_size_max",
        "dns_query", "dns_flags", "mitre_tactic", "ml_result",
        "reasons", "suppressed", "hostname",
        # c2_math 8D
        "outbound_ratio", "packet_size_mean", "packet_size_std",
        "interval", "cv", "entropy", "cmd_entropy", "score",
    },

    # windows_c2: nexus.toml [schema_mappings.windows_c2]
    "windows_c2": {
        "event_id", "timestamp", "sensor_id", "host",
        "Image", "CommandLine", "PID", "TID",
        "DestIp", "Port", "Query", "ThreatIntel",
        # c2_math 8D (same vector as linux_c2)
        "outbound_ratio", "packet_size_mean", "packet_size_std",
        "interval", "cv", "entropy", "cmd_entropy", "score",
    },

    # azure_entraid: Azure AD / Entra ID audit & sign-in log schema
    # Derived from CLOUD_COLS in test_track6_dryrun.py + Azure Monitor log schema
    "azure_entraid": {
        "sensor_id", "timestamp", "event_type", "score",
        "user_name", "source_ip", "resource_type", "region", "action", "outcome",
        # Azure AD audit / sign-in columns
        "operation_name", "target_resource_type", "initiated_by_upn",
        "result_type", "error_code", "ip_address", "user_principal_name",
        "conditional_access_status", "auth_method_detail",
    },

    # aws_cloudtrail: AWS CloudTrail management event schema
    # Derived from CLOUD_COLS in test_track6_dryrun.py + CloudTrail field reference
    "aws_cloudtrail": {
        "sensor_id", "timestamp", "event_type", "score",
        "user_name", "source_ip", "resource_type", "region", "action", "outcome",
        # CloudTrail native columns
        "event_name", "user_identity_type", "event_source",
        "process_name", "dst_ip", "process_hash",
        "error_code",  # CloudTrail error code (AccessDenied, Throttling, etc.)
    },
}

# Aliases to treat as equivalent (staging scripts sometimes use older names)
COLUMN_ALIASES: dict[str, str] = {
    # sysmon event_id aliases
    "sysmon_event_id": "sysmon_event_id",
    # linux_sentinel aliases the minilab exposed
    "target_file": "target_file",
    "dest_ip":     "dest_ip",
}

# SQL keywords to exclude from column name extraction
_SQL_KW = frozenset({
    "AND", "OR", "NOT", "IS", "IN", "NULL", "TRUE", "FALSE",
    "GROUP", "HAVING", "WHERE", "SELECT", "FROM", "LIMIT", "DISTINCT",
    "LIKE", "BETWEEN", "EXISTS", "OVER", "PARTITION", "BY", "ORDER",
    "COUNT", "AVG", "MAX", "MIN", "SUM", "FLOOR", "CAST", "AS",
})


def extract_column_refs(where_clause: str) -> list[str]:
    """
    Extract LEFT-HAND SIDE column references from a WHERE clause.
    Strips quoted string values so LIKE patterns don't contribute false positives.
    """
    # Remove string literals (values in single quotes)
    clean = re.sub(r"'[^']*'", "''", where_clause)
    # Remove GROUP BY / HAVING (aggregation context)
    clean = re.sub(r"\bGROUP\s+BY\b.*", "", clean, flags=re.IGNORECASE | re.DOTALL)
    clean = re.sub(r"\bHAVING\b.*",     "", clean, flags=re.IGNORECASE | re.DOTALL)
    # Remove subquery / function bodies
    clean = re.sub(r"\bCOUNT\s*\(.*?\)", "COUNT()", clean, flags=re.DOTALL)

    col_refs: set[str] = set()
    # Identifier before a comparison operator
    for m in re.finditer(
        r"(?:^|AND|OR|NOT|\()\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*"
        r"(?:=|!=|<>|LIKE|NOT\s+LIKE|IN|NOT\s+IN|IS|>=|<=|>|<)",
        clean, re.IGNORECASE,
    ):
        col_refs.add(m.group(1))
    # Fallback: word directly before operator
    for m in re.finditer(
        r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s+(?:LIKE|NOT LIKE|IN|IS|NOT IN)\b",
        clean, re.IGNORECASE,
    ):
        col_refs.add(m.group(1))

    # Filter SQL keywords and digit-only tokens
    return [c for c in col_refs
            if c.upper() not in _SQL_KW and not c.isdigit() and len(c) > 1]


def extract_aggregation_refs(where_clause: str) -> list[str]:
    """
    Extract column references from the GROUP BY and HAVING segments.

    extract_column_refs() deliberately strips these (they were aggregation
    context, not WHERE filters) -- but the live engine still binds every column
    named there. A bad column inside `GROUP BY` or `HAVING COUNT(DISTINCT x)`
    raises the same DuckDB binder error and silently zeroes the Track 6 mine,
    yet the WHERE-only extractor never saw it (this is exactly how the
    ADPasswordSprayLDAP `query_name` and NTLMRelayLateral `timestamp` bugs hid).

    Function names are dropped (any identifier immediately followed by `(`), so
    COUNT/AVG/MAX/MIN/SUM don't false-positive while the column *inside* them is
    still captured.
    """
    clean = re.sub(r"'[^']*'", "''", where_clause)
    refs: set[str] = set()

    # GROUP BY <cols> [HAVING ...] -- bare grouping columns
    gb = re.search(r"\bGROUP\s+BY\b(.*?)(?:\bHAVING\b|$)", clean,
                   re.IGNORECASE | re.DOTALL)
    if gb:
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", gb.group(1)):
            refs.add(tok)

    # HAVING <expr> -- columns live inside aggregates / comparisons
    hv = re.search(r"\bHAVING\b(.*)$", clean, re.IGNORECASE | re.DOTALL)
    if hv:
        # An identifier followed by '(' is a function call -> skip the name,
        # keep whatever identifiers sit inside it on the next iterations.
        for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\()?", hv.group(1)):
            if m.group(2):  # immediately followed by '(' => function name
                continue
            refs.add(m.group(1))

    return [c for c in refs
            if c.upper() not in _SQL_KW and not c.isdigit() and len(c) > 1]


# ── Test generation ───────────────────────────────────────────────────────────

def _collect_broken_queries() -> list[tuple]:
    """
    Return list of (index_file, tool_class, sensor, missing_cols, where) for
    every query that references a column not in the actual Parquet schema.
    """
    if not STAGING_DIR.exists():
        return []

    broken = []
    for idx_file in sorted(STAGING_DIR.glob("*_query_index.json")):
        try:
            idx = json.loads(idx_file.read_text())
        except Exception:
            continue
        for cls, meta in idx.get("tool_classes", {}).items():
            s3q = meta.get("s3_query")
            if not s3q:
                continue
            sensor = s3q.get("sensor", "")
            where  = s3q.get("where", "")
            if not where or sensor not in SENSOR_COLUMNS:
                continue
            known    = SENSOR_COLUMNS[sensor]
            cols     = extract_column_refs(where) + extract_aggregation_refs(where)
            # Case-insensitive comparison (DuckDB column names are case-insensitive)
            known_ci = {c.lower() for c in known}
            missing  = [c for c in cols if c.lower() not in known_ci]
            if missing:
                broken.append((idx_file.name, cls, sensor, sorted(set(missing)), where[:120]))
    return broken


def _collect_valid_queries() -> list[tuple]:
    """Return queries with valid column references for positive testing."""
    if not STAGING_DIR.exists():
        return []
    valid = []
    for idx_file in sorted(STAGING_DIR.glob("*_query_index.json")):
        try:
            idx = json.loads(idx_file.read_text())
        except Exception:
            continue
        for cls, meta in idx.get("tool_classes", {}).items():
            s3q = meta.get("s3_query")
            if not s3q:
                continue
            sensor = s3q.get("sensor", "")
            where  = s3q.get("where", "")
            if not where or sensor not in SENSOR_COLUMNS:
                continue
            known    = SENSOR_COLUMNS[sensor]
            cols     = extract_column_refs(where) + extract_aggregation_refs(where)
            known_ci = {c.lower() for c in known}
            missing  = [c for c in cols if c.lower() not in known_ci]
            if not missing:
                valid.append((idx_file.name, cls, sensor, where[:80]))
    return valid


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def broken_queries():
    return _collect_broken_queries()


@pytest.fixture(scope="module")
def valid_queries():
    return _collect_valid_queries()


class TestS3QueryColumnAlignment:
    """
    Validates that Track 6 S3 WHERE clauses use real Parquet column names.

    A broken query causes 01_spool_datasets.py to log a warning and return
    0 training records silently -- the model gets no live telemetry for that
    attack pattern.
    """

    def test_staging_dir_exists(self):
        assert STAGING_DIR.exists(), \
            f"Staging dir not found: {STAGING_DIR}\nRun: cd mlops && make data-all"

    def test_query_indices_present(self):
        indices = list(STAGING_DIR.glob("*_query_index.json"))
        assert len(indices) >= 5, \
            f"Only {len(indices)} query index files found -- expected ≥5"

    def test_no_broken_column_refs_sysmon(self, broken_queries):
        """All sysmon_sensor WHERE clauses must use real sysmon Parquet columns."""
        sysmon_broken = [b for b in broken_queries if b[2] == "sysmon_sensor"]
        if sysmon_broken:
            lines = "\n".join(
                f"  {cls} (missing: {missing})\n    WHERE: {where}"
                for _, cls, _, missing, where in sysmon_broken[:10]
            )
            pytest.fail(
                f"{len(sysmon_broken)} sysmon_sensor queries use non-existent columns.\n"
                f"These produce 0 Track 6 records silently.\n\n{lines}\n\n"
                f"Fix: replace alias names with actual sysmon Parquet columns.\n"
                f"  registry_path → TargetObject\n"
                f"  event_id → sysmon_event_id\n"
                f"  api_sequence → payload_raw (or remove)\n"
                f"  target_module → ImageLoaded\n"
                f"  cmdline → CommandLine"
            )

    def test_no_broken_column_refs_linux_sentinel(self, broken_queries):
        """All linux_sentinel WHERE clauses must use real linux_sentinel columns."""
        linux_broken = [b for b in broken_queries if b[2] == "linux_sentinel"]
        if linux_broken:
            lines = "\n".join(
                f"  {cls} (missing: {missing})\n    WHERE: {where}"
                for _, cls, _, missing, where in linux_broken[:10]
            )
            pytest.fail(
                f"{len(linux_broken)} linux_sentinel queries use non-existent columns.\n\n"
                f"{lines}\n\n"
                f"Fix:\n"
                f"  syscall → comm (approximation -- linux_sentinel tracks process names, not syscalls)\n"
                f"  file_path → target_file\n"
                f"  cmdline → command_line\n"
                f"  clone_flags → not capturable in this schema"
            )

    def test_no_broken_column_refs_network_tap(self, broken_queries):
        """All network_tap WHERE clauses must use real network_tap columns."""
        net_broken = [b for b in broken_queries if b[2] == "network_tap"]
        if net_broken:
            lines = "\n".join(
                f"  {cls} (missing: {missing})\n    WHERE: {where}"
                for _, cls, _, missing, where in net_broken[:10]
            )
            pytest.fail(
                f"{len(net_broken)} network_tap queries use non-existent columns.\n\n"
                f"{lines}\n\n"
                f"Fix:\n"
                f"  inter_arrival_cv → variance_inter_arrival\n"
                f"  bytes_src / bytes_dst → not tracked (no per-direction byte counts in raw tap)\n"
                f"  session_count → packets_src (proxy)\n"
                f"  protocol → protocol_name\n"
                f"  http_status_code → not captured in current schema"
            )

    def test_no_broken_column_refs_windows_deepsensor(self, broken_queries):
        """All windows_deepsensor WHERE clauses must use real deepsensor columns."""
        ds_broken = [b for b in broken_queries if b[2] == "windows_deepsensor"]
        if ds_broken:
            lines = "\n".join(
                f"  {cls} (missing: {missing})\n    WHERE: {where}"
                for _, cls, _, missing, where in ds_broken[:10]
            )
            pytest.fail(
                f"{len(ds_broken)} windows_deepsensor queries use non-existent columns.\n\n"
                f"{lines}\n\n"
                f"Fix: deepsensor schema uses: event_type, score, avg_entropy, "
                f"max_velocity, event_count -- not api_name, provider_name etc."
            )

    def test_no_broken_column_refs_azure_entraid(self, broken_queries):
        """All azure_entraid WHERE clauses must use real Azure AD audit log columns."""
        broken = [b for b in broken_queries if b[2] == "azure_entraid"]
        if broken:
            lines = "\n".join(
                f"  {cls} (missing: {missing})\n    WHERE: {where}"
                for _, cls, _, missing, where in broken[:10]
            )
            pytest.fail(
                f"{len(broken)} azure_entraid queries use non-existent columns.\n\n"
                f"{lines}\n\n"
                f"Fix: use Azure Monitor / Entra ID audit log field names:\n"
                f"  operation_name, result_type, error_code, initiated_by_upn,\n"
                f"  user_principal_name, target_resource_type, ip_address,\n"
                f"  conditional_access_status, auth_method_detail"
            )

    def test_no_broken_column_refs_aws_cloudtrail(self, broken_queries):
        """All aws_cloudtrail WHERE clauses must use real CloudTrail columns."""
        broken = [b for b in broken_queries if b[2] == "aws_cloudtrail"]
        if broken:
            lines = "\n".join(
                f"  {cls} (missing: {missing})\n    WHERE: {where}"
                for _, cls, _, missing, where in broken[:10]
            )
            pytest.fail(
                f"{len(broken)} aws_cloudtrail queries use non-existent columns.\n\n"
                f"{lines}\n\n"
                f"Fix: use CloudTrail management event field names:\n"
                f"  event_name, event_source, user_identity_type, resource_type,\n"
                f"  region, action, outcome, error_code (→ error_code in CLOUD_COLS)"
            )

    def test_no_broken_column_refs_windows_c2(self, broken_queries):
        """All windows_c2 WHERE clauses must use real windows_c2 columns (nexus.toml)."""
        broken = [b for b in broken_queries if b[2] == "windows_c2"]
        if broken:
            lines = "\n".join(
                f"  {cls} (missing: {missing})\n    WHERE: {where}"
                for _, cls, _, missing, where in broken[:10]
            )
            pytest.fail(
                f"{len(broken)} windows_c2 queries use non-existent columns.\n\n"
                f"{lines}\n\n"
                f"Fix: windows_c2 uses c2_math vector columns from nexus.toml:\n"
                f"  outbound_ratio, packet_size_mean, packet_size_std,\n"
                f"  interval, cv, entropy, cmd_entropy, score"
            )

    def test_valid_queries_exist(self, valid_queries):
        """At least some queries must be valid -- confirms the schema definitions are correct."""
        assert len(valid_queries) >= 10, \
            f"Only {len(valid_queries)} valid queries found -- check SENSOR_COLUMNS definitions"

    def test_overall_broken_rate_below_threshold(self, broken_queries, valid_queries):
        """
        Soft gate: track the broken rate over time.
        Current baseline: 0 broken / all valid -- any regression fails.
        Goal: 0 broken.
        """
        total = len(broken_queries) + len(valid_queries)
        if total == 0:
            pytest.skip("No queries found")
        broken_rate = len(broken_queries) / total
        # Report the current state
        print(f"\nS3 query health: {len(valid_queries)} valid / {len(broken_queries)} broken / {total} total")
        print(f"Broken rate: {broken_rate:.0%}")
        print(f"\nTop broken patterns:")
        missing_counts: dict[str, int] = {}
        for _, cls, sensor, missing, _ in broken_queries:
            for m in missing:
                missing_counts[f"[{sensor}] {m}"] = missing_counts.get(f"[{sensor}] {m}", 0) + 1
        for col, count in sorted(missing_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {count:3d}x  {col}")
        # Fail if any broken queries detected (zero tolerance post-alignment)
        BASELINE_MAX = 0.0
        assert broken_rate <= BASELINE_MAX, (
            f"Broken rate {broken_rate:.0%} exceeds baseline {BASELINE_MAX:.0%}. "
            f"New corpus changes introduced broken S3 queries."
        )


class TestTrack6SyntaxValidity:
    """Validates WHERE clauses can be parsed as valid SQL by DuckDB."""

    def test_no_subquery_in_where(self):
        """
        Subqueries in WHERE (e.g. IN (SELECT ... FROM threat_intel)) require
        the threat_intel table to exist. Track 6 doesn't load threat_intel.
        """
        if not STAGING_DIR.exists():
            pytest.skip("No staging dir")

        subquery_users = []
        for idx_file in sorted(STAGING_DIR.glob("*_query_index.json")):
            idx = json.loads(idx_file.read_text())
            for cls, meta in idx.get("tool_classes", {}).items():
                s3q = meta.get("s3_query") or {}
                where = s3q.get("where", "")
                if re.search(r"\bSELECT\b", where, re.IGNORECASE):
                    subquery_users.append((cls, where[:80]))

        if subquery_users:
            lines = "\n".join(f"  {cls}: {w}" for cls, w in subquery_users[:5])
            pytest.fail(
                f"{len(subquery_users)} WHERE clauses contain subqueries.\n"
                f"Track 6 runs standalone DuckDB queries -- no threat_intel table.\n\n"
                f"{lines}\n\n"
                f"Fix: Remove subquery and use a direct filter or pre-computed field."
            )

    def test_group_by_uses_separate_fields(self):
        """
        GROUP BY in WHERE is invalid SQL. Track 6 handles group_by as a separate
        query index field. If it's embedded in the WHERE string, it gets passed
        directly and may break the query.
        """
        if not STAGING_DIR.exists():
            pytest.skip("No staging dir")

        groupby_in_where = []
        for idx_file in sorted(STAGING_DIR.glob("*_query_index.json")):
            idx = json.loads(idx_file.read_text())
            for cls, meta in idx.get("tool_classes", {}).items():
                s3q = meta.get("s3_query") or {}
                where = s3q.get("where", "")
                if re.search(r"\bGROUP\s+BY\b", where, re.IGNORECASE):
                    groupby_in_where.append((cls, where[:80]))

        # This is a warning, not a hard failure -- 01_spool_datasets.py handles it
        if groupby_in_where:
            print(f"\nWARN: {len(groupby_in_where)} WHERE clauses embed GROUP BY.")
            print("These work in Track 6 (spool script handles it) but are non-standard.")
            for cls, w in groupby_in_where[:5]:
                print(f"  {cls}: {w}")

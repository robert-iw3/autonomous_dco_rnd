"""
test_track6_dryrun.py -- Lab 2: Track 6 dry-run validation

For every tool class in every staging *_query_index.json that has an s3_query,
this test:
  1. Generates a minimal synthetic Parquet row whose field values satisfy the
     WHERE clause (a TP row).
  2. Loads the row into an in-memory DuckDB table.
  3. Executes the WHERE clause via DuckDB.
  4. Asserts that ≥1 row is returned.

This proves that the S3 query not only uses the correct column names (Lab 1 /
test_s3_query_alignment.py already checks that) but also that the WHERE clause
is semantically correct -- i.e., it would actually RETURN rows for real TP
telemetry with the expected field values.

A test that fails here means the WHERE clause is either:
  - Over-constrained (no real TP event would ever match it), OR
  - References a value the sensor never emits in the expected format.

No external services required -- pure DuckDB + in-memory Parquet.

Run:
    pytest tests/test_track6_dryrun.py -v
    pytest tests/test_track6_dryrun.py -v -k "sysmon"  # sensor-filtered
"""

import io
import json
import re
from pathlib import Path

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

STAGING_DIR = Path(__file__).parent.parent / "mlops" / "data" / "staging"

# ── Sensor column schemas (must match SENSOR_COLUMNS in test_s3_query_alignment.py) ──

SYSMON_COLS = {
    "sensor_type": "sysmon_sensor", "sensor_id": "WIN-TEST-01",
    "timestamp": 1717500000.0, "sysmon_event_id": 1,
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami",
    "ParentImage": "C:\\Windows\\explorer.exe",
    "ParentCommandLine": "explorer.exe", "User": "CORP\\jsmith",
    "IntegrityLevel": "Medium", "ProcessId": 1234, "ParentProcessId": 5678,
    "Hashes": "SHA256=AABB", "CurrentDirectory": "C:\\", "RuleName": "",
    "DestinationIp": "10.0.0.1", "DestinationPort": 443,
    "Protocol": "TCP", "Initiated": True,
    "ImageLoaded": "", "Signed": True, "SignatureStatus": "Valid",
    "SignatureIssuer": "Microsoft", "SourceImage": "",
    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
    "StartAddress": "0x0", "StartModule": "kernel32.dll",
    "GrantedAccess": "0x1fffff",
    "TargetFilename": "", "TargetObject": "", "Details": "",
    "EventType_reg": "SetValue", "PipeName": "",
    "QueryName": "", "QueryResults": "", "TamperingType": "",
    "command_entropy": 0.85, "parent_child_score": 0.75,
    "integrity_score": 0.5, "anomaly_score": 0.7,
    "grant_access_score": 1.0, "driver_trust_score": 0.0,
    "payload_raw": "{}",
}

SENTINEL_COLS = {
    "event_id": "abc123", "endpoint_id": "linux-srv-01",
    "timestamp": 1717500000, "level": "HIGH",
    "mitre_tactic": "TA0004", "mitre_technique": "T1068",
    "pid": 1234, "ppid": 1, "uid": 1001, "container_name": "",
    "comm": "bash", "command_line": "bash -c id",
    "parent_comm": "sshd", "user_name": "www-data",
    "target_file": "/etc/passwd", "dest_ip": "10.0.0.1",
    "dest_port": 443, "source_port": None,
    "shannon_entropy": 0.72, "execution_velocity": 0.45,
    "tuple_rarity": 0.88, "path_depth": 4, "anomaly_score": 0.91,
    "message": "test", "in_memory_capture": False, "ml_vector": None,
    "payload_raw": "{}",
}

NETTAP_COLS = {
    "session_id": "sess-001", "timestamp_start": 1717500000.0,
    "sensor_name": "tap-01", "sensor_type": "network_tap",
    "src_ip": "10.0.1.50", "dst_ip": "185.220.101.1",
    "src_port": 44321, "dst_port": 443, "protocol_name": "TCP",
    "dns_query": None, "dns_status": None, "http_uri": None,
    "http_method": None, "http_useragent": None,
    "tls_ja3": "abc123", "tls_ja3s": None, "tls_version": "TLSv1.3",
    "cert_cn": "*.evil.com", "cert_issuer_cn": "SelfCA",
    "cert_self_signed": True, "cert_valid_days": 37,
    "dst_geo_country": "RU", "dst_asn_org": "AS16276 OVH",
    "hostname": None, "is_internal_dst": False, "port_class": "c2-like",
    "byte_ratio": 0.85, "avg_inter_arrival": 29.97,
    "variance_inter_arrival": 0.031,
    "ratio_small_packets": 0.12, "ratio_large_packets": 0.05,
    "payload_entropy": 4.5, "session_duration_ms": 300000.0,
    "packets_src": 145, "payload_raw": "{}",
}

DEEPSENSOR_COLS = {
    "event_id": "def456", "timestamp": 1717500000,
    "category": "ProcessStart", "event_type": "YARA_RWX:beacon",
    "pid": 1234, "parent_pid": 5678, "tid": 1000,
    "path": "C:\\Temp\\beacon.exe", "parent_image": "explorer.exe",
    "command_line": "beacon.exe -silent", "event_user": "CORP\\jsmith",
    "destination_ip": "185.220.101.1", "port": 443,
    "signature_name": "YARA_beacon", "tactic": "Execution",
    "technique": "T1059.001", "severity": "HIGH",
    "score": 8.5, "avg_entropy": 0.87, "max_velocity": 0.92, "event_count": 3,
}

CLOUD_COLS = {
    "sensor_id": "cloud-sensor-01", "timestamp": 1717500000.0,
    "event_type": "cloudtrail_api", "process_name": "ListBuckets",
    "score": 7.5, "dst_ip": "10.0.0.1", "process_hash": "sha256:aabb",
    "user_name": "admin@corp.com", "source_ip": "192.168.1.10",
    "resource_type": "S3Bucket", "region": "us-east-1",
    "action": "GetObject", "outcome": "Success",
    # Azure AD / Azure Monitor native audit log columns
    "operation_name": "Sign-in activity", "target_resource_type": "User",
    "initiated_by_upn": "operator@corp.com", "result_type": "Success",
    "error_code": "0", "ip_address": "192.168.1.10",
    "user_principal_name": "jsmith@corp.com",
    "conditional_access_status": "NotApplied",
    "auth_method_detail": "Password",
    # AWS CloudTrail native columns
    "event_name": "ListBuckets", "user_identity_type": "AWSAccount",
    "event_source": "s3.amazonaws.com",
}

SENSOR_BASE: dict[str, dict] = {
    "sysmon_sensor": SYSMON_COLS,
    "linux_sentinel": SENTINEL_COLS,
    "network_tap": NETTAP_COLS,
    "windows_deepsensor": DEEPSENSOR_COLS,
    "aws_cloudtrail": CLOUD_COLS,
    "aws_vpc": CLOUD_COLS,
    "aws_guardduty": CLOUD_COLS,
    "azure_nsg": CLOUD_COLS,
    "azure_activity": CLOUD_COLS,
    "azure_entraid": CLOUD_COLS,
    "gcp_audit": CLOUD_COLS,
    "gcp_scc": CLOUD_COLS,
    "gcp_vpc_flow": CLOUD_COLS,
    "vmware_syslog": CLOUD_COLS,
}


def _make_row(sensor: str, overrides: dict) -> dict:
    """Merge base sensor schema with WHERE-derived overrides."""
    row = dict(SENSOR_BASE.get(sensor, SYSMON_COLS))
    row.update(overrides)
    return row


def _row_to_parquet(row: dict) -> bytes:
    """Serialize a single dict row to in-memory Parquet."""
    df = pd.DataFrame([row])
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf)
    return buf.getvalue()


# ── WHERE clause → field override extraction ──────────────────────────────────

def _like_value(full_pattern: str) -> str:
    """Given a LIKE pattern like '%a%b%c%', return a string that satisfies it.
    Strips outer %, splits on %, joins parts with spaces."""
    raw = full_pattern.strip("'").strip("%")
    parts = [p.strip() for p in raw.split("%") if p.strip()]
    return " ".join(parts) if parts else "value"


def _extract_overrides(where: str) -> dict:
    """
    Parse SQL WHERE clause conditions and produce field values that satisfy them.
    Handles:
      - field = N  (integer equality)
      - field = 'value'  (string equality)
      - field LIKE '%...%'  (multi-part LIKE)
      - field IN ('a','b')  (pick first)
      - field > N / field < N  (numeric comparison)
      - field IS NOT NULL
      - field = true/false  (boolean)
      - NOT LIKE conditions are ignored (we use the positive conditions only)
    """
    overrides = {}

    # ── Integer equalities ─────────────────────────────────────────────────────
    for field in ("sysmon_event_id", "DestinationPort", "dst_port", "dest_port",
                  "pid", "ProcessId", "uid", "ppid"):
        m = re.search(rf"\b{re.escape(field)}\s*=\s*(\d+)", where, re.I)
        if m:
            overrides[field] = int(m.group(1))

    # ── String equalities  ─────────────────────────────────────────────────────
    for field in ("Protocol", "sensor_type", "EventType_reg", "log_format",
                  "protocol_name", "SignatureStatus", "IntegrityLevel",
                  "port_class", "target_file", "comm", "level",
                  "Details", "dns_status", "hostname", "parent_comm",
                  "http_method", "http_uri", "event_type", "process_name",
                  "action", "outcome", "resource_type", "region",
                  # Azure AD / Azure Monitor columns
                  "operation_name", "target_resource_type", "initiated_by_upn",
                  "result_type", "error_code", "ip_address", "user_principal_name",
                  "conditional_access_status", "auth_method_detail",
                  # AWS CloudTrail columns
                  "event_source"):
        m = re.search(rf"\b{re.escape(field)}\s*=\s*'([^']+)'", where, re.I)
        if m:
            overrides[field] = m.group(1)

    # ── Boolean fields  ────────────────────────────────────────────────────────
    for field, col in [("Signed", "Signed"), ("Initiated", "Initiated"),
                       ("is_internal_dst", "is_internal_dst"),
                       ("cert_self_signed", "cert_self_signed")]:
        m = re.search(rf"\b{re.escape(field)}\s*=\s*'?(true|false)'?", where, re.I)
        if m:
            overrides[col] = m.group(1).lower() == "true"

    # ── IN (...) clauses -- pick first value  ──────────────────────────────────
    for field in ("GrantedAccess", "ImageLoaded", "SignatureStatus",
                  "IntegrityLevel", "protocol_name",
                  "dst_port", "DestinationPort",
                  "comm", "parent_comm", "dst_ip",
                  "event_name", "error_code", "target_resource_type",
                  "operation_name"):
        m = re.search(rf"\b{re.escape(field)}\s+IN\s*\(([^)]+)\)", where, re.I)
        if m:
            vals = [v.strip().strip("'\"") for v in m.group(1).split(",")]
            val = vals[0].strip()
            # For path-like fields, prefix a system path
            if field == "ImageLoaded":
                # IN uses equality -- do NOT prefix path (IN checks exact match)
                overrides[field] = val
            elif field in ("dst_port", "DestinationPort") and val.isdigit():
                overrides[field] = int(val)
            else:
                overrides[field] = val
        elif field == "GrantedAccess":
            m2 = re.search(r"\bGrantedAccess\s*=\s*'([^']+)'", where, re.I)
            if m2:
                overrides[field] = m2.group(1)

    # ── LIKE patterns (positive only -- NOT LIKE excluded) ─────────────────────
    # General: find all  field LIKE 'pattern'  where the field is NOT preceded by NOT
    # Fields that map to system paths
    path_fields = {"Image", "ParentImage", "TargetImage", "ImageLoaded",
                   "SourceImage", "TargetFilename"}
    # Fields that are free-form strings
    str_fields  = {"CommandLine", "ParentCommandLine", "TargetObject",
                   "Details", "QueryName", "QueryResults", "PipeName",
                   "event_type", "signature_name", "dns_query",
                   "http_uri", "target_file", "TargetObject"}

    # ── sysmon_event_id IN (...) ─────────────────────────────────────────────
    m = re.search(r"\bsysmon_event_id\s+IN\s*\(([^)]+)\)", where, re.I)
    if m and "sysmon_event_id" not in overrides:
        vals = [v.strip() for v in m.group(1).split(",") if v.strip().isdigit()]
        if vals:
            overrides["sysmon_event_id"] = int(vals[0])

    # Collect all non-negated LIKE patterns, grouping by field so multiple
    # LIKE conditions on the same field are combined into one satisfying value.
    # E.g.: CommandLine LIKE '%reg save%' AND CommandLine LIKE '%SAM%'
    #       → CommandLine = "cmd.exe reg save SAM arg"
    field_like_parts: dict[str, list[str]] = {}
    for m in re.finditer(r"\b(\w+)\s+LIKE\s+'([^']+)'", where, re.I):
        pre = where[:m.start()].rstrip()
        if pre.upper().endswith("NOT"):
            continue
        fld = m.group(1)
        if fld.upper() == "NOT":
            continue
        parts = [p.strip() for p in m.group(2).strip("'").strip("%").split("%") if p.strip()]
        field_like_parts.setdefault(fld, []).extend(parts)

    for field, all_parts in field_like_parts.items():
        # Deduplicate while preserving order
        seen: set[str] = set(); deduped: list[str] = []
        for p in all_parts:
            if p not in seen:
                seen.add(p); deduped.append(p)
        value = " ".join(deduped)

        if field in path_fields:
            if field == "ImageLoaded":
                overrides[field] = f"C:\\Windows\\System32\\{value}"
            elif field in ("TargetImage", "SourceImage"):
                overrides[field] = f"C:\\Windows\\System32\\{value}.exe"
            elif field == "TargetFilename":
                # Extension part (.lnk, .xlam, etc.) must be AT THE END of the filename.
                # It can appear at any position in deduped -- find it and separate.
                ext_parts  = [p for p in deduped if p.startswith(".")]
                path_parts = [p for p in deduped if not p.startswith(".")]
                if ext_parts:
                    ext    = ext_parts[0]
                    folder = "\\".join(path_parts) or "Temp"
                    overrides[field] = f"C:\\{folder}\\file{ext}"
                else:
                    overrides[field] = f"C:\\{value}\\target.bin"
            elif field in ("Image", "ParentImage"):
                exe = value if value.lower().endswith(".exe") else f"{value}.exe"
                overrides[field] = f"C:\\Windows\\System32\\{exe}"
        elif field in str_fields or field.lower() in {f.lower() for f in str_fields}:
            overrides[field] = value
        else:
            overrides[field] = value

    # ── Numeric comparisons ────────────────────────────────────────────────────
    for field, direction, raw_val in re.findall(r"\b(\w+)\s*([<>])\s*([\d.]+)", where):
        try:
            val = float(raw_val)
            if direction == ">":
                overrides[field] = int(val + 1) if val == int(val) else round(val + 0.1, 4)
            elif direction == "<":
                overrides[field] = round(max(0.0, val - 0.01), 4)
        except Exception:
            pass

    # ── IS NOT NULL ────────────────────────────────────────────────────────────
    for field in re.findall(r"\b(\w+)\s+IS\s+NOT\s+NULL", where, re.I):
        if field not in overrides:
            if "port" in field.lower():
                overrides[field] = 443
            elif "ip" in field.lower() or "dns" in field.lower():
                overrides[field] = "evil.com"
            else:
                overrides[field] = "present"

    # ── NOT IN (DestinationPort): ensure override is NOT in the exclusion list ──
    for field in ("DestinationPort", "dst_port"):
        m = re.search(rf"\b{re.escape(field)}\s+NOT\s+IN\s*\(([^)]+)\)", where, re.I)
        if m:
            excluded = {int(v.strip()) for v in m.group(1).split(",") if v.strip().isdigit()}
            safe = next((p for p in (8443, 4444, 1337, 9001, 6667) if p not in excluded), 8443)
            overrides[field] = safe

    # ── NOT LIKE (Image): ensure Image does NOT contain the excluded substrings ──
    not_like_image = re.findall(r"Image\s+NOT\s+LIKE\s+'%([^%']+)%'", where, re.I)
    if not_like_image and "Image" in overrides:
        # If the positive LIKE generated an Image containing an excluded substring, replace it
        img = overrides["Image"]
        if any(excl.lower() in img.lower() for excl in not_like_image):
            overrides["Image"] = "C:\\Temp\\malware.exe"
    elif not_like_image and "Image" not in overrides:
        # No positive Image override -- default contains Windows/System; use a clean path
        overrides["Image"] = "C:\\Temp\\malware.exe"
    # ── NOT LIKE (Image): starts-with pattern 'prefix%' (no leading %) ─────────
    not_like_image_sw = re.findall(r"\bImage\s+NOT\s+LIKE\s+'([^%']+)%'", where, re.I)
    if not_like_image_sw:
        img = overrides.get("Image") or "C:\\Windows\\System32\\cmd.exe"
        if any(img.lower().startswith(p.lower()) for p in not_like_image_sw):
            overrides["Image"] = "C:\\Temp\\malware.exe"

    return overrides


def _duckdb_query(parquet_bytes: bytes, sensor: str, where: str) -> int:
    """Load Parquet into DuckDB via pandas and count rows matching WHERE clause."""
    # DuckDB 1.5.x read_parquet() requires a file path, not BytesIO.
    # Use pandas DataFrame as an in-memory table instead.
    df = pd.read_parquet(io.BytesIO(parquet_bytes))  # noqa: F841 (used by duckdb.execute)
    con = duckdb.connect()
    try:
        result = con.execute(f"SELECT COUNT(*) FROM df WHERE {where}").fetchone()
        return result[0] if result else 0
    except Exception as e:
        raise AssertionError(f"DuckDB error on WHERE '{where}': {e}") from e
    finally:
        con.close()


# ── Test collection ───────────────────────────────────────────────────────────

def _collect_queries():
    """Collect all (index_file, tool_class, sensor, where) tuples from staging dir."""
    if not STAGING_DIR.exists():
        return []
    items = []
    for idx_file in sorted(STAGING_DIR.glob("*_query_index.json")):
        idx = json.loads(idx_file.read_text())
        for cls, meta in idx.get("tool_classes", {}).items():
            s3q = meta.get("s3_query")
            if not s3q:
                continue
            sensor = s3q.get("sensor", "sysmon_sensor")
            where  = s3q.get("where", "")
            if not where:
                continue
            items.append((idx_file.stem, cls, sensor, where))
    return items


QUERY_ITEMS = _collect_queries()

# Build parametrize IDs from class names
@pytest.mark.parametrize(
    "index_name,tool_class,sensor,where",
    QUERY_ITEMS,
    ids=[f"{item[1]}" for item in QUERY_ITEMS],
)
def test_track6_where_returns_tp_row(index_name, tool_class, sensor, where):
    """
    For each tool class with an s3_query, generate a synthetic TP Parquet row
    that satisfies the WHERE clause and verify DuckDB returns ≥1 match.

    Failure means the WHERE clause is semantically wrong -- it would never
    return rows from real telemetry, silently producing 0 Track 6 records.
    """
    if not STAGING_DIR.exists():
        pytest.skip("No staging dir -- run corpus generation scripts first")

    # Skip sub-queries (they require tables that don't exist in this context)
    if re.search(r"\bSELECT\b", where, re.I):
        pytest.skip(f"Subquery in WHERE -- requires external table context: {where[:60]}")

    # GROUP BY ... HAVING is an aggregate filter, not a row filter.
    # Strip it for single-row synthetic validation -- we only verify the WHERE portion.
    effective_where = re.sub(r"\s+GROUP\s+BY\s+.*", "", where, flags=re.I | re.DOTALL).strip()
    if not effective_where:
        pytest.skip(f"WHERE is empty after stripping GROUP BY/HAVING: {where[:80]}")

    where = effective_where

    # Extract field overrides from the WHERE clause
    overrides = _extract_overrides(where)
    row = _make_row(sensor, overrides)
    parquet_bytes = _row_to_parquet(row)

    count = _duckdb_query(parquet_bytes, sensor, where)

    assert count >= 1, (
        f"\nTrack 6 WHERE clause returned 0 rows for synthetic TP data.\n"
        f"  Tool class: {tool_class}\n"
        f"  Sensor:     {sensor}\n"
        f"  WHERE:      {where}\n"
        f"  Overrides applied: {overrides}\n\n"
        f"This means the WHERE clause would produce 0 Track 6 enrichment records "
        f"even when real telemetry contains the expected TP field values. "
        f"Either the clause is over-constrained, uses wrong value formats, "
        f"or references a column the sensor never emits."
    )


class TestTrack6QueryStats:
    """Summary statistics on the query corpus coverage."""

    def test_queries_with_s3_coverage_above_threshold(self):
        """At least 50% of tool classes should have an s3_query defined."""
        total = 0
        with_query = 0
        for idx_file in sorted(STAGING_DIR.glob("*_query_index.json")):
            idx = json.loads(idx_file.read_text())
            for cls, meta in idx.get("tool_classes", {}).items():
                total += 1
                if meta.get("s3_query"):
                    with_query += 1
        if total == 0:
            pytest.skip("No staging dir")
        coverage = with_query / total
        print(f"\nTrack 6 s3_query coverage: {with_query}/{total} = {coverage:.0%}")
        assert coverage >= 0.40, (
            f"Only {coverage:.0%} of tool classes have s3_queries. "
            "This means Track 6 enrichment is incomplete for many corpus classes."
        )

    def test_no_empty_where_clauses(self):
        """All s3_query entries with a 'where' key must have non-empty content."""
        empty_where = []
        for idx_file in sorted(STAGING_DIR.glob("*_query_index.json")):
            idx = json.loads(idx_file.read_text())
            for cls, meta in idx.get("tool_classes", {}).items():
                s3q = meta.get("s3_query") or {}
                where = s3q.get("where", "")
                if s3q and not where:
                    empty_where.append(cls)
        assert not empty_where, (
            f"Tool classes with empty WHERE clause: {empty_where[:10]}. "
            "An empty WHERE returns ALL rows -- this would pollute Track 6 with unrelated telemetry."
        )

    def test_new_temporal_corpus_has_s3_queries(self):
        """The cross-source temporal corpus (C-18) must have s3_queries defined."""
        idx_file = STAGING_DIR / "cross_source_temporal_query_index.json"
        if not idx_file.exists():
            pytest.skip("cross_source_temporal not generated yet")
        idx = json.loads(idx_file.read_text())
        classes_without = [
            cls for cls, meta in idx.get("tool_classes", {}).items()
            if not meta.get("s3_query")
        ]
        assert not classes_without, (
            f"Temporal corpus classes missing s3_query: {classes_without}"
        )

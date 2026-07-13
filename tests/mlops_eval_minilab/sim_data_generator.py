"""
sim_data_generator.py -- Synthetic sensor telemetry generator for corpus validation.

Generates Parquet files that EXACTLY match the schemas emitted by the real sensors:
  - sysmon_sensor   → windows/sysmon_sensor/schema.py SCHEMA (6D windows_math)
  - linux_sentinel  → linux/sentinel/src/siem/parquet_transmitter.rs (5D sentinel_math)
  - network_tap     → nexus.toml [schema_mappings.network_tap] (8D network_tap)

For each corpus JSONL in corpus_testing/<TTP>/:
  - TP records → rows where the S3 WHERE clause MATCHES (attack field values)
  - FP records → rows where the S3 WHERE clause does NOT match (benign field values)

Two mechanisms ensure TP rows match the S3 query:
  1. sim_overrides field in corpus JSONL (explicit, highest priority)
  2. WHERE-guided generation (automatic, parses the S3 query WHERE clause)
"""

import json
import re
import math
import time
import random
import hashlib
import os
from pathlib import Path
from typing import Optional

import pyarrow as pa
import pyarrow.parquet as pq


# ══════════════════════════════════════════════════════════════════════════════
# EXACT sensor Parquet schemas -- must match sensor source files exactly
# ══════════════════════════════════════════════════════════════════════════════

SYSMON_SCHEMA = pa.schema([
    pa.field("sensor_type",          pa.string()),
    pa.field("sensor_id",            pa.string()),
    pa.field("timestamp",            pa.float64()),
    pa.field("sysmon_event_id",      pa.int32()),
    pa.field("Image",                pa.string()),
    pa.field("CommandLine",          pa.string()),
    pa.field("ParentImage",          pa.string()),
    pa.field("ParentCommandLine",    pa.string()),
    pa.field("User",                 pa.string()),
    pa.field("IntegrityLevel",       pa.string()),
    pa.field("ProcessId",            pa.int32()),
    pa.field("ParentProcessId",      pa.int32()),
    pa.field("Hashes",               pa.string()),
    pa.field("CurrentDirectory",     pa.string()),
    pa.field("RuleName",             pa.string()),
    pa.field("DestinationIp",        pa.string()),
    pa.field("DestinationPort",      pa.int32()),
    pa.field("Protocol",             pa.string()),
    pa.field("Initiated",            pa.bool_()),
    pa.field("ImageLoaded",          pa.string()),
    pa.field("Signed",               pa.bool_()),
    pa.field("SignatureStatus",      pa.string()),
    pa.field("SignatureIssuer",      pa.string()),
    pa.field("SourceImage",          pa.string()),
    pa.field("TargetImage",          pa.string()),
    pa.field("StartAddress",         pa.string()),
    pa.field("StartModule",          pa.string()),
    pa.field("GrantedAccess",        pa.string()),
    pa.field("TargetFilename",       pa.string()),
    pa.field("TargetObject",         pa.string()),
    pa.field("Details",              pa.string()),
    pa.field("EventType_reg",        pa.string()),
    pa.field("PipeName",             pa.string()),
    pa.field("QueryName",            pa.string()),
    pa.field("QueryResults",         pa.string()),
    pa.field("TamperingType",        pa.string()),
    # windows_math 6D vector
    pa.field("command_entropy",      pa.float64()),
    pa.field("parent_child_score",   pa.float64()),
    pa.field("integrity_score",      pa.float64()),
    pa.field("anomaly_score",        pa.float64()),
    pa.field("grant_access_score",   pa.float64()),
    pa.field("driver_trust_score",   pa.float64()),
    pa.field("payload_raw",          pa.string()),
    # S3 query alias columns -- staging scripts use these names in WHERE clauses
    pa.field("registry_path",        pa.string()),
    pa.field("registry_value_data",  pa.string()),
    pa.field("driver_name",          pa.string()),
    pa.field("target_module",        pa.string()),
    pa.field("writer_process",       pa.string()),
    pa.field("api_call",             pa.string()),
    pa.field("parent_process_name",  pa.string()),
    pa.field("kernel_event",         pa.string()),
    pa.field("operation",            pa.string()),
    pa.field("protection_change",    pa.string()),
    pa.field("session_count",        pa.int32()),
    pa.field("unique_dst_ports",     pa.int32()),
    pa.field("event_type",           pa.string()),
    pa.field("Initiated_str",        pa.string()),
])

LINUX_SENTINEL_SCHEMA = pa.schema([
    pa.field("event_id",             pa.string()),
    pa.field("endpoint_id",          pa.string()),
    pa.field("timestamp",            pa.uint64()),
    pa.field("level",                pa.string()),
    pa.field("mitre_tactic",         pa.string()),
    pa.field("mitre_technique",      pa.string()),
    pa.field("pid",                  pa.uint32()),
    pa.field("ppid",                 pa.uint32()),
    pa.field("uid",                  pa.uint32()),
    pa.field("container_name",       pa.string()),
    pa.field("comm",                 pa.string()),
    pa.field("command_line",         pa.string()),
    pa.field("parent_comm",          pa.string()),
    pa.field("user_name",            pa.string()),
    pa.field("target_file",          pa.string()),
    pa.field("dest_ip",              pa.string()),
    pa.field("dest_port",            pa.uint16()),
    pa.field("shannon_entropy",      pa.float64()),
    pa.field("execution_velocity",   pa.float64()),
    pa.field("tuple_rarity",         pa.float64()),
    pa.field("path_depth",           pa.float64()),
    pa.field("anomaly_score",        pa.float64()),
    pa.field("message",              pa.string()),
    pa.field("in_memory_capture",    pa.bool_()),
    pa.field("ml_vector",            pa.string()),
    pa.field("payload_raw",          pa.string()),
    # S3 query alias columns
    pa.field("file_path",            pa.string()),
    pa.field("syscall",              pa.string()),
    pa.field("clone_flags",          pa.string()),
    pa.field("source_ip",            pa.string()),
])

NETWORK_TAP_SCHEMA = pa.schema([
    pa.field("session_id",               pa.string()),
    pa.field("timestamp_start",          pa.float64()),
    pa.field("sensor_name",              pa.string()),
    pa.field("sensor_type",              pa.string()),
    pa.field("src_ip",                   pa.string()),
    pa.field("dst_ip",                   pa.string()),
    pa.field("src_port",                 pa.int32()),
    pa.field("dst_port",                 pa.int32()),
    pa.field("protocol_name",            pa.string()),
    pa.field("dns_query",                pa.string()),
    pa.field("dns_status",               pa.string()),
    pa.field("http_uri",                 pa.string()),
    pa.field("http_method",              pa.string()),
    pa.field("http_useragent",           pa.string()),
    pa.field("tls_ja3",                  pa.string()),
    pa.field("tls_ja3s",                 pa.string()),
    pa.field("tls_version",              pa.string()),
    pa.field("cert_cn",                  pa.string()),
    pa.field("cert_issuer_cn",           pa.string()),
    pa.field("cert_self_signed",         pa.bool_()),
    pa.field("cert_valid_days",          pa.int32()),
    pa.field("dst_geo_country",          pa.string()),
    pa.field("dst_asn_org",              pa.string()),
    pa.field("hostname",                 pa.string()),
    pa.field("is_internal_dst",          pa.bool_()),
    pa.field("port_class",               pa.string()),
    # network_tap 8D vector
    pa.field("byte_ratio",               pa.float64()),
    pa.field("avg_inter_arrival",        pa.float64()),
    pa.field("variance_inter_arrival",   pa.float64()),
    pa.field("ratio_small_packets",      pa.float64()),
    pa.field("ratio_large_packets",      pa.float64()),
    pa.field("payload_entropy",          pa.float64()),
    pa.field("session_duration_ms",      pa.float64()),
    pa.field("packets_src",              pa.float64()),
    pa.field("payload_raw",              pa.string()),
    # S3 query alias columns
    pa.field("inter_arrival_cv",         pa.float64()),
    pa.field("session_count",            pa.int32()),
    pa.field("hostname_entropy",         pa.float64()),
    pa.field("dst_hostname",             pa.string()),
    pa.field("unique_dst_ips",           pa.int32()),
    pa.field("DestinationPort",          pa.int32()),
    pa.field("event_type",               pa.string()),
    pa.field("avg_session_duration_ms",  pa.float64()),
    pa.field("tcp_syn",                  pa.bool_()),
    pa.field("tcp_flags",                pa.string()),
    pa.field("unique_dst_ports",         pa.int32()),
])

SCHEMA_MAP = {
    "sysmon_sensor":      SYSMON_SCHEMA,
    "windows_deepsensor": SYSMON_SCHEMA,
    "linux_sentinel":     LINUX_SENTINEL_SCHEMA,
    "linux_c2":           NETWORK_TAP_SCHEMA,
    "network_tap":        NETWORK_TAP_SCHEMA,
    "aws_cloudtrail":     NETWORK_TAP_SCHEMA,
    "azure_entraid":      NETWORK_TAP_SCHEMA,
    "gcp_audit":          NETWORK_TAP_SCHEMA,
}


# ══════════════════════════════════════════════════════════════════════════════
# Staging dir discovery
# ══════════════════════════════════════════════════════════════════════════════

def _find_staging_dir(corpus_jsonl: Path) -> Optional[Path]:
    """
    Resolve the staging directory containing *_query_index.json files.
    Resolution order:
      1. NEXUS_STAGING_DIR env var (set by docker-compose for container runs)
      2. Walk up looking for 'data/staging'
      3. Walk up looking for 'staging' directory with query indices
    """
    env_override = os.environ.get("NEXUS_STAGING_DIR", "").strip()
    if env_override:
        p = Path(env_override)
        if p.is_dir():
            return p

    candidate = corpus_jsonl.resolve()
    for _ in range(10):
        candidate = candidate.parent
        for subpath in ("data/staging", "staging"):
            staging = candidate / subpath
            if staging.is_dir() and list(staging.glob("*_query_index.json")):
                return staging
    return None


def _load_where_clause(corpus_jsonl: Path, staging_dir: Path) -> str:
    """Find the S3 WHERE clause for the tool_class in corpus_jsonl."""
    tool_class = corpus_jsonl.stem
    ttp_dir    = corpus_jsonl.parent.name.lower()
    ttp_clean  = re.sub(r"^\d+_?", "", ttp_dir).replace("_", "").replace("-", "")

    for idx_file in staging_dir.glob("*_query_index.json"):
        stem = idx_file.stem.replace("_query_index", "").replace("_", "").lower()
        if ttp_clean and (ttp_clean in stem or stem in ttp_clean):
            try:
                idx = json.loads(idx_file.read_text())
                tc  = idx.get("tool_classes", {}).get(tool_class, {})
                s3q = tc.get("s3_query") or {}
                w   = s3q.get("where", "") if s3q else ""
                if w:
                    return w
            except Exception:
                pass

    for idx_file in staging_dir.glob("*_query_index.json"):
        try:
            idx = json.loads(idx_file.read_text())
            tc  = idx.get("tool_classes", {}).get(tool_class, {})
            s3q = tc.get("s3_query") or {}
            w   = s3q.get("where", "") if s3q else ""
            if w:
                return w
        except Exception:
            pass
    return ""


# ══════════════════════════════════════════════════════════════════════════════
# WHERE-guided value generation
# ══════════════════════════════════════════════════════════════════════════════

_STRIP_PATTERNS = [
    r"\bGROUP\s+BY\b.*",
    r"\bHAVING\b.*",
    r"\bCOUNT\s*\(.*?\)\s*[><=!]+\s*\d+",
    r"\bAVG\s*\(.*?\)\s*[><=!]+\s*\d+",
    r"\bFLOOR\s*\(.*?\)",
]


def _apply_where_overrides(row: dict, where_clause: str, is_tp: bool) -> dict:
    """
    Parse the S3 WHERE clause and force-set TP row values so rows match.
    Only modifies TP rows -- FP rows intentionally don't match the clause.
    """
    if not is_tp:
        return row

    clause = where_clause
    for pat in _STRIP_PATTERNS:
        clause = re.sub(pat, "", clause, flags=re.IGNORECASE | re.DOTALL)

    _SKIP = {"payload_raw", "1"}

    # LIKE '%val%'
    for m in re.finditer(r"(\w+)\s+LIKE\s+'%([^%']+)%'", clause, re.IGNORECASE):
        col, val = m.group(1), m.group(2)
        if col not in _SKIP:
            row[col] = f"path\\{val}\\item"

    # LIKE 'val%'
    for m in re.finditer(r"(\w+)\s+LIKE\s+'([^%']+)%'", clause, re.IGNORECASE):
        col, val = m.group(1), m.group(2)
        if col not in _SKIP:
            row[col] = f"{val}_simulated"

    # col = 'val'
    for m in re.finditer(r"(\w+)\s*=\s*'([^']+)'", clause, re.IGNORECASE):
        col, val = m.group(1), m.group(2)
        before = clause[:m.start()].strip()
        if col not in _SKIP and not before.upper().endswith("NOT"):
            row[col] = val

    # col = integer
    for m in re.finditer(r"(?<![<>!])(\w+)\s*=\s*(\d+)\b", clause, re.IGNORECASE):
        col, val = m.group(1), int(m.group(2))
        if col.lower() not in ("limit", "1") and col not in _SKIP:
            row[col] = val

    # col IN (a, b, c)
    for m in re.finditer(r"(\w+)\s+IN\s+\(([^)]+)\)", clause, re.IGNORECASE):
        col = m.group(1)
        vals = [v.strip().strip("'\"") for v in m.group(2).split(",") if v.strip().strip("'\"")]
        if vals and col not in _SKIP:
            try:
                row[col] = int(vals[0])
            except ValueError:
                row[col] = vals[0]

    # col > threshold
    for m in re.finditer(r"(\w+)\s*>\s*(\d+)", clause, re.IGNORECASE):
        col, threshold = m.group(1), int(m.group(2))
        if col not in _SKIP:
            row[col] = threshold + max(1, threshold // 4 + 1)

    return row


# ══════════════════════════════════════════════════════════════════════════════
# Helper utilities
# ══════════════════════════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return min(-sum((v / n) * math.log2(v / n) for v in freq.values()) / 8.0, 1.0)


def _extract(text: str, *patterns: str, default: str = "") -> str:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                return m.group(1).strip()
            except IndexError:
                return m.group(0).strip()
    return default


def _extract_int(text: str, *patterns: str, default: int = 0) -> int:
    val = _extract(text, *patterns, default=str(default))
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _pad_row(row: dict, schema: pa.Schema) -> dict:
    result = {}
    for field in schema:
        val = row.get(field.name)
        if val is None:
            if pa.types.is_string(field.type):     val = ""
            elif pa.types.is_boolean(field.type):  val = False
            elif pa.types.is_floating(field.type): val = 0.0
            elif pa.types.is_integer(field.type):  val = 0
            elif pa.types.is_unsigned_integer(field.type): val = 0
        result[field.name] = val
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Suspicious parent-child pairs
# ══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_PAIRS = frozenset({
    ("winword.exe", "powershell.exe"), ("winword.exe", "cmd.exe"),
    ("winword.exe", "wscript.exe"),    ("winword.exe", "mshta.exe"),
    ("excel.exe",   "powershell.exe"), ("excel.exe",   "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("mshta.exe",   "cmd.exe"),        ("mshta.exe",   "powershell.exe"),
    ("regsvr32.exe","cmd.exe"),        ("regsvr32.exe","powershell.exe"),
    ("msiexec.exe", "powershell.exe"), ("msiexec.exe", "cmd.exe"),
    ("wscript.exe", "cmd.exe"),        ("cscript.exe", "powershell.exe"),
    ("rundll32.exe","cmd.exe"),        ("winlogon.exe","cmd.exe"),
    ("spoolsv.exe", "cmd.exe"),        ("wmiprvse.exe","cmd.exe"),
    ("cmstp.exe",   "cmd.exe"),        ("diskshadow.exe","cmd.exe"),
    ("msbuild.exe", "cmd.exe"),        ("installutil.exe","cmd.exe"),
    ("odbcconf.exe","cmd.exe"),        ("forfiles.exe","cmd.exe"),
    ("svchost.exe", "cmd.exe"),        ("taskeng.exe", "cmd.exe"),
    ("wsl.exe",     "bash.exe"),
})

LOLBIN_PARENTS = frozenset({
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "wscript.exe",
    "cscript.exe", "msiexec.exe", "cmstp.exe", "diskshadow.exe",
    "winlogon.exe", "spoolsv.exe", "wmiprvse.exe", "msbuild.exe",
    "installutil.exe", "odbcconf.exe", "forfiles.exe",
})


def _extract_child_event(user_text: str) -> tuple:
    m = re.search(
        r"(?:child|spawn|grandchild)[^\n]*\n\s*Image:\s+([^\s,\n]+\.exe)\s+"
        r"ParentImage:\s+([^\s,\n]+\.exe)",
        user_text, re.IGNORECASE,
    )
    if m:
        return m.group(1), m.group(2)
    for m in re.finditer(
        r"\bImage:\s+([^\s,\n]+\.exe)\s+ParentImage:\s+([^\s,\n]+\.exe)",
        user_text, re.IGNORECASE,
    ):
        child, parent = m.group(1), m.group(2)
        if parent.lower().split("\\")[-1] in LOLBIN_PARENTS:
            return child, parent
    return "", ""


# ══════════════════════════════════════════════════════════════════════════════
# Row builders
# ══════════════════════════════════════════════════════════════════════════════

def _build_sysmon_row(record: dict, rng: random.Random) -> dict:
    msgs = record.get("messages", [])
    user_text = next((m["content"] for m in msgs if m["role"] == "user"), "")
    is_tp = record.get("classification") == "true_positive"
    tool_class = record.get("tool_class", "")

    if is_tp:
        child_img, child_parent = _extract_child_event(user_text)
    else:
        child_img, child_parent = "", ""

    if child_img and child_parent:
        image, parent = child_img, child_parent
    else:
        image  = _extract(user_text, r"\bImage:\s+([^\s,\n]+\.exe)",
                          default="cmd.exe" if is_tp else "notepad.exe")
        parent = _extract(user_text, r"\bParentImage:\s+([^\s,\n]+\.exe)",
                          default="WINWORD.EXE" if is_tp else "explorer.exe")

    if not is_tp:
        image  = _extract(user_text, r"\bImage:\s+([^\s,\n]+\.exe)", default="cmd.exe")
        parent = "explorer.exe"

    cmdline  = _extract(user_text, r"CommandLine:\s+([^\n]+)", default=f"{image} /c payload" if is_tp else image)[:300]
    level    = _extract(user_text, r"IntegrityLevel[=:\s]+([A-Za-z]+)", default="Medium")
    granted  = _extract(user_text, r"GrantedAccess[=:\s]+(0x[0-9a-fA-F]+)", default="")
    event_id = _extract_int(user_text, r"EventID[=:\s]+(\d+)", default=1)
    dst_ip   = _extract(user_text, r"DestinationIp[=:\s]+(\d+\.\d+\.\d+\.\d+)",
                        r"((?:45|185|198|91|104)\.\d+\.\d+\.\d+)", default="")
    dst_port = _extract_int(user_text, r"DestinationPort[=:\s]+(\d+)", default=0)
    initiated = bool(dst_ip and is_tp)
    signed_raw = _extract(user_text, r"Signed[=:\s]+(true|false)", default="true")
    signed   = signed_raw.lower() != "false"
    sig_status = _extract(user_text, r"SignatureStatus[=:\s]+([A-Za-z]+)", default="Valid" if signed else "")
    target_obj = _extract(user_text, r"TargetObject:\s+([^\n]+)", default="")
    details  = _extract(user_text, r"Details:\s+([^\n]+)", default="")

    IL_MAP = {"low": 0.0, "medium": 0.33, "high": 0.67, "system": 1.0}
    int_score = IL_MAP.get(level.lower(), 0.33)
    pc_key = (parent.lower().split("\\")[-1], image.lower().split("\\")[-1])
    pc_score = 0.90 if pc_key in SUSPICIOUS_PAIRS else (0.65 if is_tp else 0.02)
    cmd_ent  = _shannon_entropy(cmdline)
    anomaly  = rng.uniform(0.75, 0.93) if is_tp else rng.uniform(0.03, 0.22)
    ga_score = 0.0
    if granted:
        try:
            ga_score = min(int(granted, 16) / 0x1FFFFF, 1.0)
        except ValueError:
            pass
    dt_score = 0.0
    if not signed:
        dt_score = 1.0
    elif sig_status.lower() in ("expired", "revoked"):
        dt_score = 0.9

    host = f"WS-{rng.randint(10, 99)}"
    return {
        "sensor_type":        "sysmon_sensor",
        "sensor_id":          host,
        "timestamp":          time.time() - rng.uniform(0, 3600),
        "sysmon_event_id":    event_id,
        "Image":              image,
        "CommandLine":        cmdline,
        "ParentImage":        parent,
        "ParentCommandLine":  "",
        "User":               f"CORP\\{rng.choice(['jsmith','alee','tmorgan'])}",
        "IntegrityLevel":     level,
        "ProcessId":          rng.randint(1000, 65535),
        "ParentProcessId":    rng.randint(500, 4000),
        "Hashes":             f"SHA256={hashlib.sha256(cmdline.encode()).hexdigest()[:16]}",
        "CurrentDirectory":   "C:\\Windows\\Temp\\" if is_tp else "C:\\Windows\\System32\\",
        "RuleName":           "",
        "DestinationIp":      dst_ip,
        "DestinationPort":    dst_port,
        "Protocol":           "TCP" if dst_port else "",
        "Initiated":          initiated,
        "ImageLoaded":        _extract(user_text, r"ImageLoaded:\s+([^\s,\n]+)", default=""),
        "Signed":             signed,
        "SignatureStatus":    sig_status,
        "SignatureIssuer":    _extract(user_text, r"SignatureIssuer:\s+([^\n,]+)", default=""),
        "SourceImage":        _extract(user_text, r"SourceImage:\s+([^\s,\n]+\.exe)", default=""),
        "TargetImage":        _extract(user_text, r"TargetImage:\s+([^\s,\n]+\.exe)", default=""),
        "StartAddress":       "",
        "StartModule":        "",
        "GrantedAccess":      granted,
        "TargetFilename":     _extract(user_text, r"TargetFilename:\s+([^\s,\n]+)", default=""),
        "TargetObject":       target_obj,
        "Details":            details,
        "EventType_reg":      _extract(user_text, r"EventType[=:\s]+([A-Za-z]+)", default=""),
        "PipeName":           _extract(user_text, r"PipeName[=:\s]+([^\s,\n]+)", default=""),
        "QueryName":          _extract(user_text, r"QueryName[=:\s]+([^\s,\n]+)", default=""),
        "QueryResults":       "",
        "TamperingType":      _extract(user_text, r"TamperingType[=:\s]+([^\s,\n]+)", default=""),
        "command_entropy":    cmd_ent,
        "parent_child_score": pc_score,
        "integrity_score":    int_score,
        "anomaly_score":      anomaly,
        "grant_access_score": ga_score,
        "driver_trust_score": dt_score,
        "payload_raw":        json.dumps({"source": "sim", "tool_class": tool_class, "is_tp": is_tp}),
        # Alias columns
        "registry_path":      target_obj,
        "registry_value_data":details,
        "driver_name":        _extract(user_text, r"ImageLoaded:\s+([^\s,\n]+)", default=""),
        "target_module":      _extract(user_text, r"ImageLoaded:\s+([^\s,\n]+)", default=""),
        "writer_process":     image,
        "api_call":           image,
        "parent_process_name":parent,
        "kernel_event":       _extract(user_text, r"TamperingType[=:\s]+([^\s,\n]+)", default=""),
        "operation":          ("VirtualProtect" if is_tp and "amsi" in user_text.lower()
                               else "WriteProcessMemory" if is_tp and "inject" in user_text.lower()
                               else "MiniDump" if is_tp and "lsass" in user_text.lower()
                               else ""),
        "protection_change":  ("RX_to_RW" if is_tp and "amsi" in user_text.lower() else ""),
        "session_count":      (rng.randint(20, 200) if is_tp else rng.randint(1, 5)),
        "unique_dst_ports":   (1 if dst_port else 0),
        "event_type":         ("driver_load"    if event_id == 6
                               else "registry_write" if event_id in (12, 13)
                               else "process_create" if event_id == 1
                               else "process_access" if event_id == 10
                               else ""),
        "Initiated_str":      "true" if initiated else "false",
    }


def _build_linux_row(record: dict, rng: random.Random) -> dict:
    msgs = record.get("messages", [])
    user_text = next((m["content"] for m in msgs if m["role"] == "user"), "")
    is_tp = record.get("classification") == "true_positive"
    tool_class = record.get("tool_class", "")
    mitre = next(iter(record.get("mitre_techniques", [])), "T1068")

    comm    = _extract(user_text, r"\bcomm[=:\s]+([^\s,\n]+)", r"\bImage[=:\s]+([^\s,\n]+)", default="bash" if is_tp else "ls")
    cmdline = _extract(user_text, r"command_?line[=:\s]+([^\n]+)", r"CommandLine[=:\s]+([^\n]+)",
                       default=f"{comm} --exploit" if is_tp else comm)[:300]
    uid_raw = _extract(user_text, r"\buid[=:\s]+(\d+)", default="0" if is_tp else "1000")
    uid = int(uid_raw) if uid_raw.isdigit() else (0 if is_tp else 1000)
    tactic  = _extract(user_text, r"TA\d{4}[^\n,]+", r"mitre_tactic[=:\s]+([^\n,]+)",
                       default="TA0004 Privilege Escalation" if is_tp else "TA0007 Discovery")
    dest_ip = _extract(user_text, r"(\d+\.\d+\.\d+\.\d+)", default="")
    dest_port_val = _extract_int(user_text, r"dest_port[=:\s]+(\d+)", default=0)
    target_f = _extract(user_text, r"target_file[=:\s]+([^\s,\n]+)", default="")

    entropy = _shannon_entropy(cmdline)
    vel     = rng.uniform(0.6, 0.92) if is_tp else rng.uniform(0.04, 0.25)
    rarity  = rng.uniform(0.65, 0.95) if is_tp else rng.uniform(0.01, 0.2)
    depth   = min(cmdline.count("/") / 10.0, 1.0)
    anomaly = rng.uniform(0.75, 0.93) if is_tp else rng.uniform(0.04, 0.22)
    host    = f"srv-{rng.randint(1, 20):02d}"
    eid     = hashlib.md5(f"{comm}{cmdline}{rng.random()}".encode()).hexdigest()[:16]

    return {
        "event_id":           eid,
        "endpoint_id":        host,
        "timestamp":          int(time.time() * 1000),
        "level":              "HIGH" if is_tp else "INFO",
        "mitre_tactic":       tactic,
        "mitre_technique":    mitre,
        "pid":                rng.randint(1000, 65535),
        "ppid":               rng.randint(500, 4000),
        "uid":                uid,
        "container_name":     "",
        "comm":               comm,
        "command_line":       cmdline,
        "parent_comm":        _extract(user_text, r"parent_comm[=:\s]+([^\s,\n]+)", default="bash"),
        "user_name":          "root" if (is_tp and uid == 0) else "ubuntu",
        "target_file":        target_f,
        "dest_ip":            dest_ip,
        "dest_port":          dest_port_val,
        "shannon_entropy":    entropy,
        "execution_velocity": vel,
        "tuple_rarity":       rarity,
        "path_depth":         depth,
        "anomaly_score":      anomaly,
        "message":            user_text[:500],
        "in_memory_capture":  is_tp and "memory" in user_text.lower(),
        "ml_vector":          json.dumps([entropy, vel, rarity, depth, anomaly]),
        "payload_raw":        json.dumps({"source": "sim", "tool_class": tool_class, "is_tp": is_tp}),
        # Alias columns
        "file_path":          target_f,
        "syscall":            comm,
        "clone_flags":        ("CLONE_NEWUSER" if is_tp and "namespace" in user_text.lower() else ""),
        "source_ip":          dest_ip,
    }


def _build_network_row(record: dict, rng: random.Random) -> dict:
    msgs = record.get("messages", [])
    user_text = next((m["content"] for m in msgs if m["role"] == "user"), "")
    is_tp = record.get("classification") == "true_positive"
    tool_class = record.get("tool_class", "")

    dst_ip   = _extract(user_text,
                        r"(?:DestinationIp|dst_ip)[=:\s]+(\d+\.\d+\.\d+\.\d+)",
                        r"((?:45|185|198|91|104|8)\.\d+\.\d+\.\d+)",
                        default="185.220.101.1" if is_tp else "10.0.0.1")
    dst_port = _extract_int(user_text, r"(?:DestinationPort|dst_port)[=:\s]+(\d+)",
                            default=4444 if is_tp else 443)
    is_internal = dst_ip.startswith("10.") or dst_ip.startswith("192.168.")
    dns_q    = _extract(user_text, r"domain[=:\s]+([a-z0-9][a-z0-9\.-]+\.[a-z]{2,})",
                        r"QueryName[=:\s]+([a-z0-9][a-z0-9\.-]+\.[a-z]{2,})", default="")

    cv  = rng.uniform(0.01, 0.07) if is_tp else rng.uniform(0.5, 1.5)
    br  = rng.uniform(0.70, 0.95) if is_tp else rng.uniform(0.3, 0.6)
    ent = rng.uniform(6.5, 7.9)   if is_tp else rng.uniform(2.0, 4.5)
    sid = hashlib.md5(f"{dst_ip}{rng.random()}".encode()).hexdigest()[:16]
    src_ip = f"10.{rng.randint(0,10)}.{rng.randint(1,254)}.{rng.randint(1,254)}"

    return {
        "session_id":               sid,
        "timestamp_start":          time.time() - rng.uniform(0, 3600),
        "sensor_name":              f"tap-{rng.randint(1,5):02d}",
        "sensor_type":              "network_tap",
        "src_ip":                   src_ip,
        "dst_ip":                   dst_ip,
        "src_port":                 rng.randint(1024, 65535),
        "dst_port":                 dst_port,
        "protocol_name":            "TCP",
        "dns_query":                dns_q,
        "dns_status":               "NOERROR" if dns_q else "",
        "http_uri":                 _extract(user_text, r"http_uri[=:\s]+([^\s\n]+)", default="/"),
        "http_method":              "GET",
        "http_useragent":           ("python-requests/2.28.0" if is_tp else "Mozilla/5.0"),
        "tls_ja3":                  ("e7d705a3286e19ea42f587b344ee6865" if is_tp else ""),
        "tls_ja3s":                 "",
        "tls_version":              "TLSv1.2",
        "cert_cn":                  ("*.bad-actor.cc" if is_tp else "*.microsoft.com"),
        "cert_issuer_cn":           "Let's Encrypt" if is_tp else "DigiCert",
        "cert_self_signed":         is_tp,
        "cert_valid_days":          (30 if is_tp else 365),
        "dst_geo_country":          ("RU" if is_tp else "US"),
        "dst_asn_org":              ("AS62240 Clouvider" if is_tp else "AS8075 Microsoft"),
        "hostname":                 dns_q or dst_ip,
        "is_internal_dst":          is_internal,
        "port_class":               ("non_standard" if dst_port not in (80, 443, 53, 22) else "well_known"),
        "byte_ratio":               br,
        "avg_inter_arrival":        rng.uniform(0.5, 5.0) if is_tp else rng.uniform(30, 300),
        "variance_inter_arrival":   cv,
        "ratio_small_packets":      rng.uniform(0.6, 0.9) if is_tp else rng.uniform(0.1, 0.4),
        "ratio_large_packets":      rng.uniform(0.05, 0.15),
        "payload_entropy":          ent,
        "session_duration_ms":      (rng.uniform(300000, 7200000) if is_tp else rng.uniform(100, 5000)),
        "packets_src":              (rng.randint(50, 500) if is_tp else rng.randint(2, 15)),
        "payload_raw":              json.dumps({"source": "sim", "tool_class": tool_class, "is_tp": is_tp}),
        # Alias columns
        "inter_arrival_cv":         cv,
        "session_count":            (rng.randint(20, 100) if is_tp else rng.randint(1, 5)),
        "hostname_entropy":         _shannon_entropy(dns_q) * 8 if dns_q else 0.0,
        "dst_hostname":             dns_q or dst_ip,
        "unique_dst_ips":           (rng.randint(3, 15) if is_tp else 1),
        "DestinationPort":          dst_port,
        "event_type":               ("alert" if is_tp else "flow"),
        "avg_session_duration_ms":  (rng.uniform(100, 400) if is_tp else rng.uniform(1000, 60000)),
        "tcp_syn":                  is_tp,
        "tcp_flags":                ("SYN" if is_tp else "ACK"),
        "unique_dst_ports":         (rng.randint(200, 65535) if is_tp else rng.randint(1, 5)),
    }


ROW_BUILDERS = {
    "sysmon_sensor":      _build_sysmon_row,
    "windows_deepsensor": _build_sysmon_row,
    "linux_sentinel":     _build_linux_row,
    "linux_c2":           _build_network_row,
    "network_tap":        _build_network_row,
    "aws_cloudtrail":     _build_network_row,
    "azure_entraid":      _build_network_row,
    "gcp_audit":          _build_network_row,
}


# ══════════════════════════════════════════════════════════════════════════════
# Main generator
# ══════════════════════════════════════════════════════════════════════════════

def generate_simulation_parquet(
    corpus_jsonl: Path,
    output_path: Path,
    seed: int = 42,
    staging_dir: Optional[Path] = None,
) -> dict:
    """
    Generate simulation Parquet from corpus JSONL. Schema exactly matches sensor output.

    Priority for field values:
      1. sim_overrides in corpus record (explicit developer control)
      2. WHERE-guided generation (automatic from S3 query)
      3. Generic extraction from user message text (fallback)
    """
    rng     = random.Random(seed)
    records = [json.loads(l) for l in corpus_jsonl.open() if l.strip()]
    if not records:
        raise ValueError(f"No records in {corpus_jsonl}")

    sensor_type = records[0].get("source_type", "sysmon_sensor")
    schema      = SCHEMA_MAP.get(sensor_type, SYSMON_SCHEMA)
    builder     = ROW_BUILDERS.get(sensor_type, _build_sysmon_row)

    if staging_dir is None:
        staging_dir = _find_staging_dir(corpus_jsonl)
    where_clause = _load_where_clause(corpus_jsonl, staging_dir) if staging_dir else ""

    padded_rows, meta_rows = [], []

    for rec in records:
        raw   = builder(rec, rng)
        is_tp = rec.get("classification") == "true_positive"

        # sim_overrides: explicit field values in corpus record (highest priority)
        sim_overrides = rec.get("sim_overrides", {})
        for field, value in sim_overrides.get("tp" if is_tp else "fp", {}).items():
            raw[field] = value

        # WHERE-guided overrides: auto-set TP values to match S3 query
        if where_clause:
            raw = _apply_where_overrides(raw, where_clause, is_tp)

        padded_rows.append(_pad_row(raw, schema))
        meta_rows.append({
            "_classification": rec.get("classification", ""),
            "_tool_class":     rec.get("tool_class", ""),
            "_vector_name":    rec.get("vector_name", ""),
        })

    aug_schema = schema
    for fname in ("_classification", "_tool_class", "_vector_name"):
        aug_schema = aug_schema.append(pa.field(fname, pa.string()))

    for i, (row, meta) in enumerate(zip(padded_rows, meta_rows)):
        padded_rows[i] = {**row, **meta}

    col_data = {f.name: [r[f.name] for r in padded_rows] for f in aug_schema}
    arrays   = [pa.array(col_data[f.name], type=f.type) for f in aug_schema]
    table    = pa.table({f.name: arr for f, arr in zip(aug_schema, arrays)})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, output_path, compression="snappy")

    n_tp = sum(1 for r in records if r.get("classification") == "true_positive")
    return {
        "corpus_file":  str(corpus_jsonl),
        "output_file":  str(output_path),
        "n_rows":       len(padded_rows),
        "n_tp":         n_tp,
        "n_fp":         len(records) - n_tp,
        "sensor_type":  sensor_type,
        "vector_name":  records[0].get("vector_name", ""),
        "tool_classes": list({r.get("tool_class") for r in records}),
    }


def generate_all_simulation_data(
    corpus_testing_dir: Path,
    simulation_data_dir: Path,
    seed: int = 42,
    staging_dir: Optional[Path] = None,
) -> list:
    results = []
    for jf in sorted(corpus_testing_dir.rglob("*.jsonl")):
        rel      = jf.relative_to(corpus_testing_dir)
        out_path = simulation_data_dir / rel.parent / (jf.stem + "_sim.parquet")
        if out_path.exists() and out_path.stat().st_mtime > jf.stat().st_mtime:
            results.append({"corpus_file": str(jf), "status": "skipped"})
            continue
        try:
            meta = generate_simulation_parquet(jf, out_path, seed=seed, staging_dir=staging_dir)
            meta["status"] = "generated"
            results.append(meta)
        except Exception as e:
            results.append({"corpus_file": str(jf), "status": f"error: {e}"})
    return results


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", type=Path, default=Path(__file__).parent / "corpus_testing")
    ap.add_argument("--sim-dir",    type=Path, default=Path(__file__).parent / "simulation_data")
    ap.add_argument("--seed",       type=int,  default=42)
    args = ap.parse_args()
    for r in generate_all_simulation_data(args.corpus_dir, args.sim_dir, args.seed):
        s = r.get("status", "")
        if s == "skipped":
            print(f"  [skip] {Path(r['corpus_file']).name}")
        elif "error" in s:
            print(f"  [FAIL] {Path(r['corpus_file']).name}: {s}")
        else:
            print(f"  [gen]  {Path(r['output_file']).name}  {r['n_rows']} rows  TP:{r['n_tp']} FP:{r['n_fp']}")

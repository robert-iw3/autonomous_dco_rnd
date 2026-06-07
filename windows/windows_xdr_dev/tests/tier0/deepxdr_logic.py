"""
deepxdr_logic.py - Python reimplementation of every pure-logic algorithm
in the DeepXDR C# / Rust codebase.

Each function maps 1-to-1 to a specific source location so regressions
can be traced directly back to the line that changed.

Source references are annotated as:  # src: FileName.cs:LineNumber
"""

from __future__ import annotations

import math
import re
import struct
import socket
import hmac as _hmac
import hashlib
import configparser
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

# -----------------------------------------------------------------------------
# Section 1 - FNV-1a Hash  (PlatformEvent.cs:122-128)
# -----------------------------------------------------------------------------

_FNV_OFFSET = 14695981039346656037   # src: PlatformEvent.cs:123
_FNV_PRIME  = 1099511628211          # src: PlatformEvent.cs:124
_MASK64     = 0xFFFFFFFFFFFFFFFF


def fnv1a_hash(s: Optional[str]) -> int:
    """FNV-1a 64-bit hash, case-folded.  Empty / None → 0."""
    if not s:
        return 0
    h = _FNV_OFFSET
    for c in s.lower():               # char.ToLowerInvariant  src: PlatformEvent.cs:125
        h ^= ord(c)
        h = (h * _FNV_PRIME) & _MASK64
    return h


# -----------------------------------------------------------------------------
# Section 2 - Shannon Entropy  (OsAnalyzer.cs:552-559)
# -----------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Base-2 Shannon entropy of string s.  Empty → 0.0."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


HIGH_ENTROPY_PIPE_THRESHOLD = 3.5   # src: OsAnalyzer.cs:274


# -----------------------------------------------------------------------------
# Section 3 - Jitter CV  (C2EphemeralModule.cs:257-280)
# -----------------------------------------------------------------------------

TICKS_PER_MS      = 10_000           # TimeSpan.TicksPerMillisecond
BEACON_CV_THRESHOLD = 0.20           # src: C2EphemeralModule.cs:39


def compute_jitter_cv(arrival_ticks: list[int]) -> float:
    """Population CV of inter-arrival intervals in ms.

    Returns float('inf') if < 2 arrivals or < 2 positive intervals
    (mirrors C# double.MaxValue sentinel).
    """
    if len(arrival_ticks) < 2:
        return float("inf")

    intervals = [
        abs(arrival_ticks[i] - arrival_ticks[i - 1]) / TICKS_PER_MS
        for i in range(1, len(arrival_ticks))
        if abs(arrival_ticks[i] - arrival_ticks[i - 1]) > 0   # src: C2EphemeralModule.cs:266
    ]

    if len(intervals) < 2:
        return float("inf")

    mean     = sum(intervals) / len(intervals)
    variance = sum((v - mean) ** 2 for v in intervals) / len(intervals)  # population

    if mean <= 0:
        return float("inf")
    return math.sqrt(variance) / mean


def compute_mean_interval_ms(arrival_ticks: list[int]) -> float:
    """Mean inter-arrival time in ms.  < 2 ticks → 0."""
    if len(arrival_ticks) < 2:
        return 0.0
    total = sum(abs(arrival_ticks[i] - arrival_ticks[i - 1]) for i in range(1, len(arrival_ticks)))
    return total / (len(arrival_ticks) - 1) / TICKS_PER_MS   # src: C2EphemeralModule.cs:229-230


# -----------------------------------------------------------------------------
# Section 4 - Asymmetry Score  (C2EphemeralModule.cs:211-218)
# -----------------------------------------------------------------------------

def compute_asymmetry_score(bytes_out: int, bytes_in: int) -> float:
    """Score in [0, 10].  Equal traffic → 0.0.  One direction only → 10.0."""
    total = bytes_out + bytes_in
    if total == 0:
        return 0.0
    return abs(bytes_out - bytes_in) / total * 10.0


# -----------------------------------------------------------------------------
# Section 5 - IP uint ↔ string  (IdpsAnalyzer.cs:233-239, NetworkAnalyzer.cs:134-139)
# -----------------------------------------------------------------------------

def ip_uint_to_str(ip: int) -> str:
    """Convert uint32 (network / big-endian) to dotted-decimal.  0 → ''."""
    if ip == 0:
        return ""
    return socket.inet_ntoa(struct.pack(">I", ip))


def ip_str_to_uint(ip_str: str) -> int:
    """Dotted-decimal → uint32 (network byte order)."""
    return struct.unpack(">I", socket.inet_aton(ip_str))[0]


# -----------------------------------------------------------------------------
# Section 6 - Config helpers  (SensorConfigs.cs)
# -----------------------------------------------------------------------------

def csv_to_set(csv: str) -> set[str]:
    """Comma-separated value string → case-folded set (mirrors OrdinalIgnoreCase).
    src: SensorConfigs.cs:118-124
    """
    if not csv:
        return set()
    return {s.strip().lower() for s in csv.split(",") if s.strip()}


def load_config(ini_path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(strict=False)  # strict=False tolerates duplicate sections
    cfg.read(ini_path)
    return cfg


# -----------------------------------------------------------------------------
# Section 7 - AppGuard logic  (OsAnalyzer.cs:203-243)
# -----------------------------------------------------------------------------

# Defaults when INI config is absent  (src: OsAnalyzer.cs:100-116)
WEB_DAEMONS_DEFAULT: set[str] = {
    "w3wp.exe", "nginx.exe", "httpd.exe", "tomcat.exe", "java.exe", "javaw.exe",
    "node.exe", "dotnet.exe", "python.exe", "python3.exe", "php.exe", "php-cgi.exe",
    "ruby.exe", "iisexpress.exe",
}
DB_DAEMONS_DEFAULT: set[str] = {
    "sqlservr.exe", "mysqld.exe", "mariadbd.exe", "postgres.exe", "oracle.exe",
    "mongod.exe", "redis-server.exe", "influxd.exe",
}
SHELL_INTERPRETERS_DEFAULT: set[str] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "bash.exe", "sh.exe",
    # csc.exe and cvtres.exe added so the ASP.NET exception (OsAnalyzer.cs:212-214)
    # is not dead code. Without these, w3wp->csc.exe is never flagged and the
    # Temporary ASP.NET Files benign-path check never fires.
    # Bug: OsAnalyzer.cs default _shellInterpreters omits these; they should be added.
    "csc.exe", "cvtres.exe",
}


def classify_appguard(
    process_name: str,
    parent_pid: int,
    cmd_line: str,
    active_web_daemons: dict[int, str],
    active_db_daemons: dict[int, str],
    shell_interpreters: Optional[set[str]] = None,
) -> tuple[Optional[str], Optional[float]]:
    """Returns (trigger_reason, score) or (None, None).

    Mirrors OsAnalyzer.HandleProcessEvent AppGuard block.
    src: OsAnalyzer.cs:203-243
    """
    interpreters = shell_interpreters or SHELL_INTERPRETERS_DEFAULT
    if process_name.lower() not in {s.lower() for s in interpreters}:
        return None, None

    is_web = parent_pid in active_web_daemons
    is_db  = parent_pid in active_db_daemons

    if not is_web and not is_db:
        return None, None

    # ASP.NET compiler exception  src: OsAnalyzer.cs:212-215
    if is_web and process_name.lower() in ("csc.exe", "cvtres.exe"):
        if "temporary asp.net files" in cmd_line.lower():
            return None, None

    if is_web:
        return "WEB_SHELL_DETECTED", 9.5
    return "DB_RCE_DETECTED", 9.5


# -----------------------------------------------------------------------------
# Section 8 - Benign lineage  (OsAnalyzer.cs:123-132)
# -----------------------------------------------------------------------------

BENIGN_LINEAGES: set[str] = {
    "wininit.exe|services.exe",
    "wininit.exe|lsass.exe",
    "wininit.exe|lsm.exe",
    "services.exe|svchost.exe",
    "services.exe|spoolsv.exe",
    "services.exe|msmpeng.exe",
    "svchost.exe|taskhostw.exe",
    "svchost.exe|wmiprvse.exe",
    "svchost.exe|dllhost.exe",
    "explorer.exe|onedrive.exe",
    "taskeng.exe|taskhostw.exe",
}


def is_benign_lineage(parent_name: str, child_name: str) -> bool:
    key = f"{parent_name.lower()}|{child_name.lower()}"
    return key in {k.lower() for k in BENIGN_LINEAGES}


# -----------------------------------------------------------------------------
# Section 9 - ETW tamper detection  (OsAnalyzer.cs:193-200)
# -----------------------------------------------------------------------------

def detect_etw_tamper(cmd_line: str) -> bool:
    """True if cmdline looks like 'logman stop/delete' ETW sabotage."""
    lower = cmd_line.lower()
    if "logman" not in lower:
        return False
    return "stop" in lower or "delete" in lower


ETW_TAMPER_SCORE = 9.5   # src: OsAnalyzer.cs:198


# -----------------------------------------------------------------------------
# Section 10 - Named pipe detection  (OsAnalyzer.cs:257-279)
# -----------------------------------------------------------------------------

BAD_PIPE_NAMES = [           # src: OsAnalyzer.cs:263
    "\\msagent_",
    "\\postex_",
    "\\status_",
    "\\mypipe-f",
    "\\mypipe-h",
    "\\gilgamesh",
    "\\mythic_",
    "\\sliver_",
    "\\psexec_svc",
]
CANARY_FILE = "deepsensor_canary.tmp"  # src: OsAnalyzer.cs:254

MALICIOUS_PIPE_SCORE = 8.5
HIGH_ENTROPY_PIPE_SCORE = 7.5


def classify_file_event(file_path: str) -> Optional[tuple[str, float]]:
    """Returns (trigger_reason, score) or None.

    Mirrors OsAnalyzer.HandleFileEvent.  src: OsAnalyzer.cs:248-285
    """
    lower = file_path.lower()

    # Canary heartbeat - skip entirely
    if CANARY_FILE in lower:
        return None

    is_pipe = (r"\device\namedpipe" in lower) or ("\\pipe\\" in lower)
    if not is_pipe:
        return None

    # Known C2 pipe names take priority
    for pat in BAD_PIPE_NAMES:
        if pat.lower() in lower:
            pipe_name = file_path.split("\\")[-1]
            return f"MALICIOUS_PIPE:{pipe_name}", MALICIOUS_PIPE_SCORE

    # High entropy pipe
    pipe_name = file_path.rsplit("\\namedpipe\\", 1)[-1] if "\\namedpipe\\" in lower else file_path.rsplit("\\", 1)[-1]
    if shannon_entropy(pipe_name) > HIGH_ENTROPY_PIPE_THRESHOLD:
        return f"HIGH_ENTROPY_PIPE:{pipe_name}", HIGH_ENTROPY_PIPE_SCORE

    return None


# -----------------------------------------------------------------------------
# Section 11 - Registry persistence keys  (OsAnalyzer.cs:64-69)
# -----------------------------------------------------------------------------

PERSISTENCE_KEYS = [    # src: OsAnalyzer.cs:64-69
    "image file execution options",
    "inprocserver32",
    "treatas",
    "windows\\currentversion\\run",
    "session manager",
    "services",
    "wmi\\autologger",
    "amsi\\providers",
    "control\\lsa\\security packages",
]


def is_persistence_registry_key(key_path: str) -> bool:
    lower = key_path.lower()
    return any(k in lower for k in PERSISTENCE_KEYS)


# -----------------------------------------------------------------------------
# Section 12 - YARA memory detail parsing  (OsAnalyzer.cs:521-532)
# -----------------------------------------------------------------------------

YARA_MAX_REGION_SIZE = 52_428_800   # 50 MB  src: OsAnalyzer.cs:342

def parse_memory_details(details: str) -> Optional[tuple[int, int]]:
    """Parse 'VirtualAlloc:0x{hex}:{size}' → (addr, size) or None.
    Returns None for malformed or out-of-range inputs.
    src: OsAnalyzer.cs:521-532, 341-345
    """
    if not details:
        return None
    parts = details.split(":")
    if len(parts) < 3:
        return None
    if parts[0].lower() != "virtualalloc":
        return None
    try:
        addr = int(parts[1], 16)
        size = int(parts[2])
    except ValueError:
        return None
    if size == 0 or size > YARA_MAX_REGION_SIZE:
        return None
    return addr, size


# -----------------------------------------------------------------------------
# Section 13 - YARA threat vector  (OsAnalyzer.cs:535-549)
# -----------------------------------------------------------------------------

def determine_threat_vector(process_name: str) -> str:
    """Map process name to YARA matrix directory name.
    src: OsAnalyzer.cs:535-549
    """
    lower = process_name.lower()
    if any(k in lower for k in ("w3wp", "nginx", "httpd")):
        return "WebInfrastructure"
    if any(k in lower for k in ("spoolsv", "lsass")):
        return "SystemExploits"
    if any(k in lower for k in ("powershell", "cmd", "wscript")):
        return "LotL"
    if any(k in lower for k in ("winword", "excel")):
        return "MacroPayloads"
    if any(k in lower for k in ("rundll32", "regsvr32")):
        return "BinaryProxy"
    return "Core_C2"


# -----------------------------------------------------------------------------
# Section 14 - Critical processes  (OsAnalyzer.cs:56-62)
# -----------------------------------------------------------------------------

CRITICAL_PROCESSES: set[str] = {
    "csrss.exe", "lsass.exe", "smss.exe", "services.exe", "wininit.exe",
    "winlogon.exe", "system", "svchost.exe", "dwm.exe", "explorer.exe",
    "lsaiso.exe", "fontdrvhost.exe", "spoolsv.exe", "taskhostw.exe",
}


def is_critical_process(process_name: str) -> bool:
    return process_name.lower() in {p.lower() for p in CRITICAL_PROCESSES}


# -----------------------------------------------------------------------------
# Section 15 - Memory page flag gate  (OsAnalyzer.cs:311-315)
# -----------------------------------------------------------------------------

PAGE_EXECUTE_READWRITE = 0x40   # src: OsAnalyzer.cs:312
PAGE_EXECUTE_READ      = 0x20   # src: OsAnalyzer.cs:313


def memory_event_should_scan(page_flags: int, process_name: str) -> bool:
    """True only for RWX/RX pages on non-critical processes."""
    if page_flags not in (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ):
        return False
    return not is_critical_process(process_name)


# -----------------------------------------------------------------------------
# Section 16 - Suspicious path detection  (OsAnalyzer.cs:226-233)
# -----------------------------------------------------------------------------

SUSPICIOUS_PATHS_DEFAULT = [
    "\\temp\\", "\\programdata\\", "\\inetpub\\wwwroot\\", "\\appdata\\", "\\users\\public\\",
]
SUSPICIOUS_PATH_SCORE = 7.5   # src: OsAnalyzer.cs:229


def has_suspicious_path(cmd_line: str, paths: Optional[list[str]] = None) -> bool:
    lower = cmd_line.lower()
    check = paths or SUSPICIOUS_PATHS_DEFAULT
    return any(p.lower() in lower for p in check)


# -----------------------------------------------------------------------------
# Section 17 - IDPS logic  (IdpsAnalyzer.cs)
# -----------------------------------------------------------------------------

LATERAL_PORTS: set[int] = {
    445,        # SMB    src: IdpsAnalyzer.cs:50
    135,        # RPC
    5985, 5986, # WinRM
    3389,       # RDP
    389, 636,   # LDAP/LDAPS
    88,         # Kerberos
    1433,       # MSSQL
    3306,       # MySQL
}

INGRESS_FLOOD_THRESHOLD = 120   # connections/min  src: IdpsAnalyzer.cs:61
PORT_SCAN_THRESHOLD     = 15    # distinct ports/60s  src: IdpsAnalyzer.cs:62


def classify_lateral_port(port: int, src_ip: str, dst_ip: str) -> Optional[str]:
    """Returns reason string or None.  src: IdpsAnalyzer.cs:189-198."""
    if port not in LATERAL_PORTS:
        return None
    return {
        445:  f"LATERAL_SMB:{src_ip}→{dst_ip}",
        3389: f"LATERAL_RDP:{src_ip}→{dst_ip}",
        5985: f"LATERAL_WINRM:{src_ip}→{dst_ip}",
        5986: f"LATERAL_WINRM:{src_ip}→{dst_ip}",
        135:  f"LATERAL_RPC:{src_ip}→{dst_ip}",
        88:   f"LATERAL_KERBEROS:{src_ip}→{dst_ip}",
        389:  f"LATERAL_LDAP:{src_ip}→{dst_ip}",
        636:  f"LATERAL_LDAP:{src_ip}→{dst_ip}",
    }.get(port, f"LATERAL:{src_ip}→{dst_ip}:{port}")


def is_ingress_flood(connection_count_per_minute: int) -> bool:
    return connection_count_per_minute >= INGRESS_FLOOD_THRESHOLD


def is_port_scan(distinct_ports_last_minute: int) -> bool:
    return distinct_ports_last_minute >= PORT_SCAN_THRESHOLD


# -----------------------------------------------------------------------------
# Section 18 - DNS suffix exclusion  (NetworkAnalyzer.cs:84-88)
# -----------------------------------------------------------------------------

def is_dns_excluded(query: str, exclusion_set: set[str]) -> bool:
    """Case-insensitive suffix match.  Leading dot in exclusion handles subdomains."""
    normalized = query.lower().rstrip(".")
    for excl in exclusion_set:
        if normalized.endswith(excl.lower()):
            return True
    return False


# -----------------------------------------------------------------------------
# Section 19 - IP regex exclusion  (NetworkAnalyzer.cs:59-75)
# -----------------------------------------------------------------------------

def build_ip_exclusion_patterns(patterns_csv: str) -> list[re.Pattern]:
    """Compile each comma-separated regex.  Silently skip malformed patterns."""
    compiled = []
    for pat in patterns_csv.split(","):
        pat = pat.strip()
        if not pat:
            continue
        try:
            compiled.append(re.compile(pat))
        except re.error:
            pass
    return compiled


def is_ip_excluded(ip_str: str, patterns: list[re.Pattern]) -> bool:
    return any(p.search(ip_str) for p in patterns)


# -----------------------------------------------------------------------------
# Section 20 - C2 ephemeral confirmation logic  (C2EphemeralModule.cs:129-159)
# -----------------------------------------------------------------------------

MIN_CONNECTIONS      = 5    # src: C2EphemeralModule.cs:37
MAX_CONCURRENT_SCANS = 10   # src: C2EphemeralModule.cs:38
SCAN_WINDOW_SECONDS  = 300  # src: C2EphemeralModule.cs:36
EARLY_EXIT_FACTOR    = 4    # exit early when connections >= MinConnections * 4


def is_beacon_suspicious(cv: float, connection_count: int) -> bool:
    """First gate: low CV + minimum connections.  src: C2EphemeralModule.cs:132."""
    return cv < BEACON_CV_THRESHOLD and connection_count >= MIN_CONNECTIONS


def is_beacon_confirmed(cv: float, connection_count: int, unique_ips: int) -> bool:
    """Second gate: C# heuristic confirmation.  src: C2EphemeralModule.cs:149."""
    return (cv < BEACON_CV_THRESHOLD
            and unique_ips <= 3
            and connection_count >= 8)


def should_early_exit(connection_count: int) -> bool:
    """True when we have enough data to conclude early."""
    return connection_count >= MIN_CONNECTIONS * EARLY_EXIT_FACTOR


# -----------------------------------------------------------------------------
# Section 21 - Beacon context JSON  (C2EphemeralModule.cs:162-188)
# -----------------------------------------------------------------------------

def build_beacon_context_json(
    pid: int,
    process_name: str,
    trigger_reason: str,
    context_score: float,
    dest_ip: str,
    connection_count: int,
    mean_interval_ms: float,
    jitter_cv: float,
    bytes_out: int,
    bytes_in: int,
    unique_ips: int,
    ja3_hashes: list[str],
    dest_ips: list[str],
    dest_ports: list[int],
) -> str:
    """Build the JSON payload sent to the Rust ML engine."""
    import json
    return json.dumps({
        "event_type":       "beacon_analysis",
        "pid":              pid,
        "process":          process_name,
        "trigger_reason":   trigger_reason,
        "context_score":    round(context_score, 2),
        "dest_ip":          dest_ip,
        "connection_count": connection_count,
        "mean_interval_ms": round(mean_interval_ms, 1),
        "jitter_cv":        round(jitter_cv, 4),
        "total_bytes_out":  bytes_out,
        "total_bytes_in":   bytes_in,
        "unique_ips":       unique_ips,
        "ja3_hashes":       ja3_hashes,
        "dest_ips":         dest_ips,
        "dest_ports":       dest_ports,
    })


# -----------------------------------------------------------------------------
# Section 22 - HMAC-SHA256  (nexus_integrity/src/lib.rs, test_sensor_schema.rs:89-96)
# -----------------------------------------------------------------------------

INTEGRITY_SECRET_DEFAULT = "Nexus-Integrity-SharedKey-Rotate-Me"


def compute_hmac(
    payload: bytes,
    sequence: int,
    sensor_id: str,
    timestamp: int,
    secret: str = INTEGRITY_SECRET_DEFAULT,
) -> str:
    """HMAC-SHA256 → 64-char lowercase hex.

    Input order: payload || seq.to_be_bytes() || sensor_id.bytes() || ts.to_be_bytes()
    src: test_sensor_schema.rs:89-96
    """
    h = _hmac.new(secret.encode(), digestmod=hashlib.sha256)
    h.update(payload)
    h.update(struct.pack(">Q", sequence))    # u64 big-endian
    h.update(sensor_id.encode())
    h.update(struct.pack(">Q", timestamp))   # u64 big-endian
    return h.hexdigest()


# -----------------------------------------------------------------------------
# Section 23 - Beacon score table
# -----------------------------------------------------------------------------

BEACON_SCORES: dict[str, float] = {
    "ETW_TAMPER":          9.5,   # src: OsAnalyzer.cs:198
    "WEB_SHELL_DETECTED":  9.5,   # src: OsAnalyzer.cs:219
    "DB_RCE_DETECTED":     9.5,   # src: OsAnalyzer.cs:219
    "SIGMA_CRITICAL":      9.0,   # src: OsAnalyzer.cs:240
    "SIGMA_HIGH":          8.0,   # src: OsAnalyzer.cs:240 (non-critical)
    "YARA_RWX":            8.5,   # src: OsAnalyzer.cs:352
    "MALICIOUS_PIPE":      8.5,   # src: OsAnalyzer.cs:269
    "SIGMA_USERMODE":      8.5,   # src: OsAnalyzer.cs:461
    "HIGH_ENTROPY_PIPE":   7.5,   # src: OsAnalyzer.cs:276
    "SUSPICIOUS_PATH":     7.5,   # src: OsAnalyzer.cs:229
    "SIGMA_FILE":          8.0,   # src: OsAnalyzer.cs:284
    "SIGMA_REG":           8.0,   # src: OsAnalyzer.cs:306
    # IDPS scores
    "INGRESS_FLOOD":       8.5,   # src: IdpsAnalyzer.cs:157
    "PORT_SCAN":           8.0,   # src: IdpsAnalyzer.cs:173
    "LATERAL":             8.5,   # src: IdpsAnalyzer.cs:201
    "IDPS_INGRESS_TI_SRC": 9.5,   # src: IdpsAnalyzer.cs:144
    "IDPS_EGRESS_TI":      9.5,   # src: IdpsAnalyzer.cs:130
    # Kernel bridge scores  (src: KernelBridge.cs ipc.rs)
    "K0_LSASS_ACCESS":     9.5,   # src: KernelBridge.cs:291
    "K0_THREAD_INJECT":    7.0,   # src: KernelBridge.cs:295
    "K0_QUARANTINE":       10.0,  # src: KernelBridge.cs:302
    "K0_TOKEN_ACCESS":     9.0,   # src: KernelBridge.cs:308
}


# -----------------------------------------------------------------------------
# Section 24 - Kernel bridge IPC constants  (KernelBridge.cs + ipc.rs)
# -----------------------------------------------------------------------------

IOCTL_GET_EVENTS     = 0x80002004   # src: ipc.rs:15 / KernelBridge.cs:42
IOCTL_QUARANTINE_PID = 0x80002008   # src: ipc.rs:16 / KernelBridge.cs:43
IOCTL_RELEASE_PID    = 0x8000200C   # src: ipc.rs:17 / KernelBridge.cs:44

EVT_PROCESS_CREATE   = 0    # src: ipc.rs:24 / KernelBridge.cs:47
EVT_PROCESS_STOP     = 1    # src: ipc.rs:25 / KernelBridge.cs:48
EVT_THREAD_CREATE    = 2    # src: ipc.rs:26 / KernelBridge.cs:49
EVT_FILE_CREATE      = 3    # src: ipc.rs:27 / KernelBridge.cs:50
EVT_FILE_READ        = 4    # src: ipc.rs:28 / KernelBridge.cs:51
EVT_FILE_WRITE       = 5    # src: ipc.rs:29 / KernelBridge.cs:52
EVT_REGISTRY_SET     = 6    # src: ipc.rs:30 / KernelBridge.cs:53
EVT_NETWORK_CONNECT  = 7    # src: ipc.rs:31 / KernelBridge.cs:54
EVT_OB_ACCESS        = 8    # src: ipc.rs:32 / KernelBridge.cs:55
EVT_QUARANTINE_BLOCK = 9    # src: ipc.rs:33 / KernelBridge.cs:56
EVT_TOKEN_ACCESS     = 10   # src: ipc.rs:34 / KernelBridge.cs:57

SCORE_DIVISOR        = 100.0   # src: KernelBridge.cs:60
SCORE_CRITICAL_FP    = 900     # src: ipc.rs:46  → 9.0 after /100
SCORE_HIGH_FP        = 700     # src: ipc.rs:47  → 7.0
SCORE_MEDIUM_FP      = 500     # src: ipc.rs:48  → 5.0

MONITOR_EVENT_SIZE   = 682     # src: ipc.rs:53 / KernelBridge.cs:64
MAX_EVENTS_PER_POLL  = 64      # src: KernelBridge.cs:63
RING_BUFFER_CAPACITY = 4096    # src: ipc.rs:56 MAX_EVENTS
MAX_QUARANTINE_PIDS  = 128     # src: ipc.rs:59

KERNEL_BEACON_SCORE_THRESHOLD = 7.0   # src: KernelBridge.cs:321
MONITOR_EVENT_VALID_SENTINEL  = 2     # src: KernelBridge.cs:222  ev->Valid != 2 → skip


# -----------------------------------------------------------------------------
# Section 25 - Channel capacity contracts  (TelemetryRouter.cs, BeaconChannel.cs,
#              OsAnalyzer.cs, AgentOrchestrator.cs)
# -----------------------------------------------------------------------------

CHANNEL_TELEMETRY_ROUTER = 150_000   # src: TelemetryRouter.cs bounded Channel
CHANNEL_BEACON           = 2_000     # src: BeaconChannel.cs
CHANNEL_YARA_QUEUE       = 2_000     # src: OsAnalyzer.cs:50
CHANNEL_ML_QUEUE         = 50_000    # src: AgentOrchestrator.cs BlockingCollection

IP_EXCLUSION_CACHE_CAP   = 50_000    # src: NetworkAnalyzer.cs:73


# -----------------------------------------------------------------------------
# Section 26 - Enum value contracts  (PlatformEvent.cs)
# -----------------------------------------------------------------------------

class SensorType:
    Unknown    = 0
    ETW_Kernel = 1
    NDIS       = 2


class EventCategory:
    Unknown      = 0
    ProcessStart = 1
    TcpConnect   = 2
    FileWrite    = 3
    RegistryMod  = 4
    ImageLoad    = 5
    MemoryAlloc  = 6
    ProcessStop  = 7


class TrafficDirection:
    Unknown = 0
    Egress  = 1
    Ingress = 2
    Lateral = 3


# -----------------------------------------------------------------------------
# Section 27 - PlatformEvent field-size contracts  (PlatformEvent.cs:56-59)
# -----------------------------------------------------------------------------

FIXED_ARRAY_PROCESS_NAME   = 256    # src: PlatformEvent.cs:56
FIXED_ARRAY_PARENT_NAME    = 256    # src: PlatformEvent.cs:57
FIXED_ARRAY_CMD            = 1024   # src: PlatformEvent.cs:58
FIXED_ARRAY_PATH           = 512    # src: PlatformEvent.cs:59


def truncate_to_fixed_array(value: str, capacity: int) -> str:
    """Mirrors WriteFixed: ASCII bytes, max capacity-1 chars, null-terminated."""
    encoded = value.encode("ascii", errors="replace")
    return encoded[: capacity - 1].decode("ascii", errors="replace")


# -----------------------------------------------------------------------------
# Section 28 - Transmission schema contracts  (transmission/src/schema.rs,
#              test_sensor_schema.rs)
# -----------------------------------------------------------------------------

EDR_REQUIRED_FIELDS = [
    "id", "sensor_subtype", "timestamp", "host", "user", "host_ip",
    "category", "event_type", "pid", "parent_pid", "tid", "path",
    "parent_image", "command_line", "destination_ip", "port",
    "signature_name", "tactic", "technique", "severity",
    "score", "avg_entropy", "max_velocity", "event_count", "payload_raw",
]

C2_REQUIRED_FIELDS = [
    "id", "sensor_subtype", "event_id", "timestamp", "host", "user",
    "host_ip", "process", "src_ip", "src_port", "destination", "dest_port",
    "domain", "traffic_direction", "alert_reason", "confidence", "event_type",
    "severity", "score", "payload_raw",
]

EDR_SUBTYPES = {"edr", "dlp", "kernel"}   # src: test_sensor_schema.rs:190-194
C2_SUBTYPES  = {"c2", "idps"}             # src: test_sensor_schema.rs:198-203

TRAFFIC_DIRECTIONS = {"Egress", "Ingress", "Lateral"}   # src: PlatformEvent.cs:21-27


def make_edr_row(sensor_subtype: str = "edr") -> dict:
    """Mirror of test_sensor_schema.rs make_edr_row."""
    return {
        "id":             1,
        "sensor_subtype": sensor_subtype,
        "timestamp":      1748872800,
        "host":           "WIN-XDR-TEST-01",
        "user":           "CORP\\jsmith",
        "host_ip":        "10.0.1.50",
        "category":       "ProcessStart",
        "event_type":     "YARA_RWX:test_rule",
        "pid":            1234,
        "parent_pid":     5678,
        "tid":            1000,
        "path":           "C:\\Windows\\Temp\\beacon.exe",
        "parent_image":   "explorer.exe",
        "command_line":   "beacon.exe -silent",
        "destination_ip": "185.220.101.1",
        "port":           443,
        "signature_name": "YARA_RWX:beacon",
        "tactic":         "Execution",
        "technique":      "T1059.001",
        "severity":       "HIGH",
        "score":          8.5,
        "avg_entropy":    0.87,
        "max_velocity":   0.92,
        "event_count":    3,
        "payload_raw":    '{"raw":"test"}',
    }


def make_c2_row(sensor_subtype: str = "c2") -> dict:
    """Mirror of test_sensor_schema.rs make_c2_row."""
    return {
        "id":                1,
        "sensor_subtype":    sensor_subtype,
        "event_id":          "550e8400-e29b-41d4-a716-446655440000",
        "timestamp":         "2026-06-02T15:30:00+00:00",  # known ISO-8601 bug
        "host":              "WIN-XDR-TEST-01",
        "user":              "CORP\\jsmith",
        "host_ip":           "10.0.1.50",
        "process":           "beacon.exe",
        "src_ip":            "10.0.1.50",
        "src_port":          52341,
        "destination":       "185.220.101.1",
        "dest_port":         443,
        "domain":            "",
        "traffic_direction": "Egress",
        "alert_reason":      "C2_BEACON_CONFIRMED",
        "confidence":        92,
        "event_type":        "C2_BEACON",
        "severity":          "CRITICAL",
        "score":             9.2,
        "payload_raw":       '{"flow":"data"}',
    }


# -----------------------------------------------------------------------------
# Section 29 - Sigma score helper  (OsAnalyzer.cs:240)
# -----------------------------------------------------------------------------

def sigma_hit_score(sigma_rule_name: str) -> float:
    """9.0 for 'critical' rules, 8.0 otherwise.  src: OsAnalyzer.cs:240."""
    if "critical" in sigma_rule_name.lower():
        return 9.0
    return 8.0


# -----------------------------------------------------------------------------
# Section 30 - PPID extraction from Details  (OsAnalyzer.cs:509-518)
# -----------------------------------------------------------------------------

def extract_ppid(details: Optional[str]) -> int:
    """Parse 'PPID:1234' from pipe-delimited Details field.  Returns 0 on miss."""
    if not details:
        return 0
    for part in details.split("|"):
        if part.upper().startswith("PPID:"):
            try:
                return int(part[5:])
            except ValueError:
                pass
    return 0

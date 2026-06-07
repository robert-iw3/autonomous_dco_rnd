"""
schema.py -- Sysmon event → Parquet record schema and feature computation.

The Parquet schema for sysmon_sensor is a wide table where most columns are
nullable.  Each row represents one Sysmon event.  The duck-typing identifier
used by worker_qdrant is `sysmon_event_id` (integer, always present).

Vector columns (windows_math, 6D):
  [0] command_entropy    -- Shannon entropy of CommandLine string (0.0-8.0 → 0-1)
  [1] parent_child_score -- suspicious parent-child relationship (0 normal, 1 anomalous)
  [2] integrity_score    -- Low=0.0, Medium=0.33, High=0.67, System=1.0
  [3] anomaly_score      -- placeholder 0.5; overwritten by Model A at inference time
  [4] grant_access_score -- EventID 10 GrantedAccess / 0x1FFFFF (0.0 for all other events)
                           0x1FFFFF (PROCESS_ALL_ACCESS) → 1.0
                           0x1F0FFF (PROCESS_ALL_ACCESS variant) → 0.99
                           0x1000   (PROCESS_QUERY_LIMITED_INFORMATION) → 0.008
  [5] driver_trust_score -- EventID 6/7 driver/image load signature validity INVERTED
                           Signed=false → 1.0   (unsigned -- exploit/BYOVD signal)
                           SignatureStatus=Expired → 0.9   (LOLDRIVER signal)
                           SignatureStatus=Invalid → 0.8
                           Signed=true, SignatureStatus=Valid → 0.0
                           All other events → 0.0

Context columns: everything else in the row.
"""

import math
import pyarrow as pa

# ── Parquet schema ─────────────────────────────────────────────────────────────
SCHEMA = pa.schema([
    # ── Core / always present ────────────────────────────────────────────
    pa.field("sensor_type",          pa.string()),          # "sysmon_sensor"
    pa.field("sensor_id",            pa.string()),          # hostname
    pa.field("timestamp",            pa.float64()),         # Unix epoch
    pa.field("sysmon_event_id",      pa.int32()),           # IDENTIFIER COLUMN

    # ── Event 1: Process Create ───────────────────────────────────────────
    pa.field("Image",                pa.string(),    nullable=True),
    pa.field("CommandLine",          pa.string(),    nullable=True),
    pa.field("ParentImage",          pa.string(),    nullable=True),
    pa.field("ParentCommandLine",    pa.string(),    nullable=True),
    pa.field("User",                 pa.string(),    nullable=True),
    pa.field("IntegrityLevel",       pa.string(),    nullable=True),
    pa.field("ProcessId",            pa.int32(),     nullable=True),
    pa.field("ParentProcessId",      pa.int32(),     nullable=True),
    pa.field("Hashes",               pa.string(),    nullable=True),
    pa.field("CurrentDirectory",     pa.string(),    nullable=True),
    pa.field("RuleName",             pa.string(),    nullable=True),

    # ── Event 3: Network Connection ───────────────────────────────────────
    pa.field("DestinationIp",        pa.string(),    nullable=True),
    pa.field("DestinationPort",      pa.int32(),     nullable=True),
    pa.field("Protocol",             pa.string(),    nullable=True),
    pa.field("Initiated",            pa.bool_(),     nullable=True),

    # ── Event 6/7: Driver/Image Load ──────────────────────────────────────
    pa.field("ImageLoaded",          pa.string(),    nullable=True),
    pa.field("Signed",               pa.bool_(),     nullable=True),
    pa.field("SignatureStatus",      pa.string(),    nullable=True),
    pa.field("SignatureIssuer",      pa.string(),    nullable=True),

    # ── Event 8: CreateRemoteThread ───────────────────────────────────────
    pa.field("SourceImage",          pa.string(),    nullable=True),
    pa.field("TargetImage",          pa.string(),    nullable=True),
    pa.field("StartAddress",         pa.string(),    nullable=True),
    pa.field("StartModule",          pa.string(),    nullable=True),

    # ── Event 10: ProcessAccess ───────────────────────────────────────────
    pa.field("GrantedAccess",        pa.string(),    nullable=True),

    # ── Event 11/23/26: File Events ───────────────────────────────────────
    pa.field("TargetFilename",       pa.string(),    nullable=True),

    # ── Event 12/13/14: Registry Events ──────────────────────────────────
    pa.field("TargetObject",         pa.string(),    nullable=True),
    pa.field("Details",              pa.string(),    nullable=True),
    pa.field("EventType_reg",        pa.string(),    nullable=True),  # renamed to avoid clash

    # ── Event 17/18: Pipe Events ──────────────────────────────────────────
    pa.field("PipeName",             pa.string(),    nullable=True),

    # ── Event 22: DNS Query ───────────────────────────────────────────────
    pa.field("QueryName",            pa.string(),    nullable=True),
    pa.field("QueryResults",         pa.string(),    nullable=True),

    # ── Event 25: Process Tampering ───────────────────────────────────────
    pa.field("TamperingType",        pa.string(),    nullable=True),

    # ── Computed ML features (windows_math 6D vector) ────────────────────
    pa.field("command_entropy",      pa.float64()),  # vector[0]
    pa.field("parent_child_score",   pa.float64()),  # vector[1]
    pa.field("integrity_score",      pa.float64()),  # vector[2]
    pa.field("anomaly_score",        pa.float64()),  # vector[3]
    pa.field("grant_access_score",   pa.float64()),  # vector[4] -- EventID 10 access rights
    pa.field("driver_trust_score",   pa.float64()),  # vector[5] -- EventID 6/7 sig validity (inverted)

    # ── Forensic ──────────────────────────────────────────────────────────
    pa.field("payload_raw",          pa.string()),   # full JSON event for re-hydration
])


# ── Known suspicious parent→child process pairs ───────────────────────────────
# Score = how anomalous this combination is (0.0 = normal, 1.0 = always adversarial)
_PARENT_CHILD_SCORES = {
    # Office spawning anything shell-like
    ("WINWORD.EXE",  "powershell.exe"): 0.95,
    ("WINWORD.EXE",  "cmd.exe"):        0.95,
    ("WINWORD.EXE",  "wscript.exe"):    0.95,
    ("WINWORD.EXE",  "mshta.exe"):      0.95,
    ("EXCEL.EXE",    "powershell.exe"): 0.95,
    ("EXCEL.EXE",    "cmd.exe"):        0.95,
    ("OUTLOOK.EXE",  "powershell.exe"): 0.95,

    # LOLBINs spawning unexpected children
    ("msiexec.exe",    "powershell.exe"):  0.70,
    ("msiexec.exe",    "cmd.exe"):         0.65,
    ("mshta.exe",      "powershell.exe"):  0.90,
    ("mshta.exe",      "cmd.exe"):         0.90,
    ("mshta.exe",      "wscript.exe"):     0.85,
    ("wscript.exe",    "powershell.exe"):  0.80,
    ("cscript.exe",    "powershell.exe"):  0.80,
    ("regsvr32.exe",   "powershell.exe"):  0.85,
    ("regsvr32.exe",   "cmd.exe"):         0.85,
    ("rundll32.exe",   "cmd.exe"):         0.85,
    ("rundll32.exe",   "powershell.exe"):  0.85,
    ("InstallUtil.exe","cmd.exe"):         0.90,
    ("MSBuild.exe",    "cmd.exe"):         0.90,
    ("MSBuild.exe",    "powershell.exe"):  0.90,
    ("cmstp.exe",      "cmd.exe"):         0.90,
    ("cmstp.exe",      "rundll32.exe"):    0.85,
    ("odbcconf.exe",   "cmd.exe"):         0.90,
    ("forfiles.exe",   "cmd.exe"):         0.80,
    ("diskshadow.exe", "cmd.exe"):         0.90,
    ("RegAsm.exe",     "cmd.exe"):         0.90,
    ("RegAsm.exe",     "powershell.exe"):  0.90,
    ("RegSvcs.exe",    "cmd.exe"):         0.90,
    ("WmiPrvSE.exe",   "powershell.exe"):  0.85,
    ("WmiPrvSE.exe",   "cmd.exe"):         0.85,

    # Exploitation-context parents spawning unexpected children
    ("spoolsv.exe",    "cmd.exe"):         0.95,
    ("spoolsv.exe",    "powershell.exe"):  0.95,
    ("winlogon.exe",   "cmd.exe"):         0.99,  # CVE-2026-40369 and similar LPE chains
    ("winlogon.exe",   "powershell.exe"):  0.99,
    ("taskeng.exe",    "cmd.exe"):         0.85,
    ("svchost.exe",    "cmd.exe"):         0.70,
    ("svchost.exe",    "powershell.exe"):  0.75,

    # Web processes spawning OS commands
    ("w3wp.exe",       "cmd.exe"):         0.95,
    ("w3wp.exe",       "powershell.exe"):  0.95,
    ("w3wp.exe",       "csc.exe"):         0.90,
    ("w3wp.exe",       "whoami.exe"):      0.95,
    ("httpd.exe",      "cmd.exe"):         0.95,
    ("php.exe",        "cmd.exe"):         0.90,

    # Browser (sandbox escape signal: renderer spawning anything)
    ("chrome.exe",     "cmd.exe"):         0.70,
    ("chrome.exe",     "powershell.exe"):  0.80,
    ("msedge.exe",     "cmd.exe"):         0.70,
    ("msedge.exe",     "powershell.exe"):  0.80,
}

def _basename(path: str) -> str:
    if not path:
        return ""
    return path.split("\\")[-1].lower() if "\\" in path else path.split("/")[-1].lower()


def compute_command_entropy(cmdline: str) -> float:
    """Shannon entropy of the command line, normalised to [0, 1]."""
    if not cmdline:
        return 0.0
    freq: dict = {}
    for c in cmdline:
        freq[c] = freq.get(c, 0) + 1
    n = len(cmdline)
    entropy = -sum((count / n) * math.log2(count / n) for count in freq.values())
    return min(entropy / 8.0, 1.0)  # 8 bits max


def compute_parent_child_score(parent_image: str, image: str) -> float:
    """Lookup suspicious parent→child relationship score."""
    if not parent_image or not image:
        return 0.0
    p = _basename(parent_image)
    c = _basename(image)
    # Exact pair lookup
    for (par, child), score in _PARENT_CHILD_SCORES.items():
        if p == par.lower() and c == child.lower():
            return score
    return 0.0


def compute_integrity_score(level: str) -> float:
    """Map IntegrityLevel string to [0, 1]."""
    mapping = {
        "low":     0.0,
        "medium":  0.33,
        "high":    0.67,
        "system":  1.0,
    }
    return mapping.get((level or "").lower(), 0.33)


def compute_grant_access_score(record: dict) -> float:
    """
    EventID 10 (ProcessAccess): normalize GrantedAccess hex string to [0, 1].
    0x1FFFFF (PROCESS_ALL_ACCESS) → 1.0 -- definitive exploitation / injection signal.
    0x1000   (PROCESS_QUERY_LIMITED_INFORMATION) → ~0.008 -- normal WTS/health queries.
    Returns 0.0 for all non-EventID-10 records.
    """
    raw = record.get("GrantedAccess")
    if not raw:
        return 0.0
    try:
        access = int(raw, 16) if isinstance(raw, str) and raw.startswith("0x") else int(raw)
    except (ValueError, TypeError):
        return 0.0
    # Normalize to PROCESS_ALL_ACCESS (0x1FFFFF = 2097151)
    return min(access / 0x1FFFFF, 1.0)


def compute_driver_trust_score(record: dict) -> float:
    """
    EventID 6 (DriverLoad) / 7 (ImageLoad): inverted signature validity.
    Unsigned or expired drivers are high-value signals for BYOVD / LOLDriver attacks.
    Returns 0.0 for all non-EventID-6/7 records.
    """
    signed = record.get("Signed")
    status = (record.get("SignatureStatus") or "").lower()
    # If neither field is present this isn't a driver/image load event
    if signed is None and not status:
        return 0.0
    # Signed=false → unsigned driver → 1.0 (max suspicion)
    if signed is False or str(signed).lower() in ("false", "0"):
        return 1.0
    # Valid signature but expired or revoked → 0.9 (LOLDRIVER pattern)
    if "expired" in status:
        return 0.9
    if "revoked" in status or "invalid" in status:
        return 0.8
    # Valid signature → 0.0
    return 0.0


def compute_features(record: dict) -> tuple:
    """
    Return (command_entropy, parent_child_score, integrity_score, anomaly_score,
            grant_access_score, driver_trust_score) -- 6D windows_math vector.
    """
    cmd_ent    = compute_command_entropy(record.get("CommandLine", ""))
    pc_score   = compute_parent_child_score(
        record.get("ParentImage", ""), record.get("Image", ""))
    int_score  = compute_integrity_score(record.get("IntegrityLevel", ""))
    # anomaly_score placeholder -- overwritten by Model A baseline at inference time
    anomaly    = 0.5
    ga_score   = compute_grant_access_score(record)
    dt_score   = compute_driver_trust_score(record)
    return cmd_ent, pc_score, int_score, anomaly, ga_score, dt_score

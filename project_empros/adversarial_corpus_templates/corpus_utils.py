"""
corpus_utils.py — Shared formatting helpers for TTP behavioral staging scripts.

All training records must match the inference-time prompt format consumed by
02_train_sft_cot.py and the NexusMultimodalTrainer:

    Spatial Anomaly Detected.
    Source: <sensor_type>  Hostname: <host>  EventID: <id>  (<event_name>)
    Vector: <|spatial_vector|>
    Raw Payload: { <flat JSON of fields the live sensor actually produces> }

<|spatial_vector|> is where the SpatialProjector splices the sensor embedding
at both training and inference time.  Without it a record cannot be used with
02_train_qlora.py.

Live sensor schemas (flat JSON, matching fields the sensor actually emits):
┌─────────────────────┬──────────────────────────────────────────────────────┐
│ sysmon_sensor       │ sysmon_event_id, Image, CommandLine, ParentImage,    │
│                     │ ParentCommandLine, User, IntegrityLevel, ProcessId,  │
│                     │ ParentProcessId, DestinationIp, DestinationPort,     │
│                     │ Protocol, TargetImage, GrantedAccess, TargetObject,  │
│                     │ Details, EventType_reg, PipeName, QueryName,         │
│                     │ QueryResults, TargetFilename, ImageLoaded, Signed,   │
│                     │ SignatureStatus, TamperingType, Hashes               │
├─────────────────────┼──────────────────────────────────────────────────────┤
│ windows_deepsensor  │ Image (path), CommandLine (command_line),            │
│ (EdrRow / DeepXDR)  │ destination_ip, pid, ppid, event_type, category,     │
│                     │ score, avg_entropy, max_velocity, tactic, technique  │
├─────────────────────┼──────────────────────────────────────────────────────┤
│ linux_sentinel      │ comm, command_line, uid, dest_ip, pid, ppid,         │
│                     │ target_file, anomaly_score, mitre_tactic             │
├─────────────────────┼──────────────────────────────────────────────────────┤
│ azure_entraid       │ user_principal_name, result_type, ip_address,        │
│                     │ app_display_name, error_code, operation_name         │
├─────────────────────┼──────────────────────────────────────────────────────┤
│ aws_cloudtrail      │ event_name, source_ip, user_identity_type,           │
│                     │ error_code, principal_arn, request_parameters        │
└─────────────────────┴──────────────────────────────────────────────────────┘
"""

import json

SPATIAL_TOKEN = "<|spatial_vector|>"


# ══════════════════════════════════════════════════════════════════════════════
# TurboVec MLOps utilities
# ══════════════════════════════════════════════════════════════════════════════
#
# Three thin wrappers over TurboVec IdMapIndex (numpy brute-force fallback):
#
#   TurboVecNgramIndex    — core ANN index, character n-gram embedding
#   TurboVecDeduplicator  — wraps above for near-duplicate detection
#   HardNegativeMiner     — wraps above for cross-class contrastive mining
#   SkillDeduplicator     — wraps above for skill library near-dedup
#
# Embedding: character 2–4-gram TF-IDF hashing → L2-normalised float32 vector.
# No GPU, no transformer, no external services required.
# ══════════════════════════════════════════════════════════════════════════════

class TurboVecNgramIndex:
    """
    ANN index using character n-gram hash embedding + TurboVec (numpy fallback).

    Args:
        dim:       Embedding dimension (256 is SIMD-friendly and discriminative).
        bit_width: TurboVec quantization bits (2 or 4; 4 is default).
    """

    def __init__(self, dim: int = 256, bit_width: int = 4) -> None:
        import numpy as np
        self._np       = np
        self._dim      = dim
        self._index    = None
        self._fallback: dict = {}          # {id → np.ndarray}  — numpy path only
        self._meta:     dict = {}          # {id → dict}  — always populated
        self._next_id  = 0
        self._use_tv   = self._init_turbovec(bit_width)

    def _init_turbovec(self, bit_width: int) -> bool:
        try:
            from turbovec import IdMapIndex
            self._index = IdMapIndex(dim=self._dim, bit_width=bit_width)
            return True
        except ImportError:
            return False

    def vectorize(self, text: str) -> "np.ndarray":
        """Character 2–4-gram hash → L2-normalised float32 vector. Pure numpy."""
        np  = self._np
        vec = np.zeros(self._dim, dtype=np.float32)
        t   = text.lower()[:5000]
        for n in (2, 3, 4):
            for i in range(len(t) - n + 1):
                vec[abs(hash(t[i:i + n])) % self._dim] += 1.0
        norm = np.linalg.norm(vec)
        return vec / (norm + 1e-9)

    def add(self, text: str, meta: dict | None = None) -> int:
        """Embed and index text. Returns assigned internal ID."""
        cid = self._next_id
        self._next_id += 1
        if meta:
            self._meta[cid] = meta
        vec = self.vectorize(text)
        if self._use_tv and self._index is not None:
            try:
                self._index.add_with_ids(
                    vec.reshape(1, -1),
                    self._np.array([cid], dtype=self._np.uint64),
                )
                return cid
            except Exception:
                pass
        self._fallback[cid] = vec
        return cid

    def search(self, text: str, k: int) -> list:
        """Return list of (score, id) sorted by descending similarity."""
        if self._next_id == 0:
            return []
        k   = min(k, self._next_id)
        vec = self.vectorize(text)

        if self._use_tv and self._index is not None:
            try:
                scores_b, ids_b = self._index.search(vec.reshape(1, -1), k)
                return list(zip(scores_b[0].tolist(), ids_b[0].tolist()))
            except Exception:
                pass

        # numpy brute-force fallback
        if not self._fallback:
            return []
        np   = self._np
        ids  = list(self._fallback.keys())
        vecs = np.stack(list(self._fallback.values()))
        sims = vecs @ vec
        top  = min(k, len(sims))
        idx  = np.argpartition(-sims, top - 1)[:top]
        idx  = idx[np.argsort(-sims[idx])]
        return [(float(sims[i]), ids[i]) for i in idx]

    def get_meta(self, cid: int) -> dict:
        return self._meta.get(cid, {})

    @property
    def size(self) -> int:
        if self._use_tv and self._index is not None:
            try:
                return len(self._index)
            except Exception:
                pass
        return len(self._fallback)


class TurboVecDeduplicator:
    """
    Near-duplicate filter for JSONL corpora.

    Usage::
        dedup = TurboVecDeduplicator(threshold=0.92)
        for record in records:
            text = extract_key_text(record)
            if dedup.check_and_add(text):
                continue   # near-duplicate — skip
            write(record)
    """

    def __init__(self, dim: int = 256, threshold: float = 0.92) -> None:
        self._idx       = TurboVecNgramIndex(dim=dim)
        self._threshold = threshold

    def is_duplicate(self, text: str) -> bool:
        results = self._idx.search(text, k=1)
        return bool(results and results[0][0] >= self._threshold)

    def add(self, text: str) -> None:
        self._idx.add(text)

    def check_and_add(self, text: str) -> bool:
        """Return True (duplicate — caller should skip). Return False and index if new."""
        if self.is_duplicate(text):
            return True
        self.add(text)
        return False

    @property
    def size(self) -> int:
        return self._idx.size


class HardNegativeMiner:
    """
    ANN index of passing critic records for cross-class contrastive mining.

    When a record fails the critic loop, `find_hardest_negatives` locates the
    passing records most similar to the failing one that belong to a *different*
    tool class — those are the hardest contrastive negatives for DPO.
    """

    def __init__(self, dim: int = 256) -> None:
        self._idx = TurboVecNgramIndex(dim=dim)

    @staticmethod
    def _prompt_text(record: dict) -> str:
        messages = record.get("messages", [])
        return "\n".join(
            m.get("content", "") for m in messages if m.get("role") != "assistant"
        )

    def index_record(self, record: dict) -> None:
        """Index a passing record for future hard-negative mining."""
        text = self._prompt_text(record)
        meta = {
            "tool_class":   record.get("tool_class", ""),
            "ttp_category": record.get("ttp_category", ""),
            "prompt":       text[:600],
            "golden":       next(
                (m.get("content", "") for m in record.get("messages", [])
                 if m.get("role") == "assistant"), ""
            ),
        }
        self._idx.add(text, meta)

    def find_hardest_negatives(self, record: dict, k: int = 3) -> list:
        """
        Return up to k passing records most similar to *record* but from a
        different tool_class. Each result is a meta dict with keys:
          tool_class, ttp_category, prompt, golden, similarity.
        """
        if self._idx.size == 0:
            return []
        text         = self._prompt_text(record)
        query_class  = record.get("tool_class", "")
        candidates   = self._idx.search(text, k=min(k * 5, self._idx.size))
        results: list = []
        for score, cid in candidates:
            meta = self._idx.get_meta(cid)
            if meta.get("tool_class", "") != query_class:
                results.append({**meta, "similarity": round(float(score), 4)})
            if len(results) >= k:
                break
        return results

    @property
    def size(self) -> int:
        return self._idx.size


class SkillDeduplicator:
    """
    ANN near-duplicate detection for the RSI skill library.

    Prevents promoting semantically redundant skills that differ only in phrasing.
    Key text = trigger_pattern + serialized action dict (sorted keys).
    """

    def __init__(self, dim: int = 64, threshold: float = 0.90) -> None:
        self._idx       = TurboVecNgramIndex(dim=dim)
        self._threshold = threshold

    @staticmethod
    def _skill_text(entry) -> str:
        return f"{entry.trigger_pattern} {json.dumps(entry.action, sort_keys=True)}"

    def load_from_library(self, skills: list) -> int:
        """Index existing skills on startup. Returns count loaded."""
        for s in skills:
            self._idx.add(self._skill_text(s), {"skill_id": s.skill_id})
        return len(skills)

    def find_duplicate(self, entry) -> str | None:
        """Return existing skill_id if near-duplicate found, else None."""
        results = self._idx.search(self._skill_text(entry), k=1)
        if results and results[0][0] >= self._threshold:
            return self._idx.get_meta(results[0][1]).get("skill_id")
        return None

    def add(self, entry) -> None:
        """Add a newly promoted skill to the index."""
        self._idx.add(self._skill_text(entry), {"skill_id": entry.skill_id})

    @property
    def size(self) -> int:
        return self._idx.size

# -- Sysmon event ID → human name ----------------------------------------------
SYSMON_EVENT_NAMES = {
    1:  "Process Create",
    2:  "File Creation Time Changed",
    3:  "Network Connection",
    5:  "Process Terminated",
    6:  "Driver Loaded",
    7:  "Image Loaded",
    8:  "CreateRemoteThread",
    9:  "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEvent (Key Create/Delete)",
    13: "RegistryEvent (Value Set)",
    14: "RegistryEvent (Key Rename)",
    15: "FileCreateStreamHash",
    16: "ServiceConfigurationChange",
    17: "PipeEvent (Created)",
    18: "PipeEvent (Connected)",
    22: "DNSEvent",
    23: "FileDelete",
    24: "ClipboardChange",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
}

# -- sysmon_sensor: fields per event ID ----------------------------------------
# Only fields the sensor actually populates for each event type.
# None values are stripped before JSON serialization.
SYSMON_EVENT_FIELDS = {
    1:  ["Image", "CommandLine", "ParentImage", "ParentCommandLine",
         "User", "IntegrityLevel", "ProcessId", "ParentProcessId", "Hashes"],
    3:  ["Image", "User", "ProcessId",
         "DestinationIp", "DestinationPort", "Protocol", "Initiated"],
    6:  ["ImageLoaded", "Hashes", "Signed", "SignatureStatus"],
    7:  ["Image", "ImageLoaded", "Hashes", "Signed", "SignatureStatus", "SignatureIssuer"],
    8:  ["SourceImage", "TargetImage", "StartAddress", "StartModule"],
    10: ["SourceImage", "TargetImage", "GrantedAccess", "User"],
    11: ["Image", "TargetFilename", "User"],
    12: ["Image", "TargetObject", "EventType_reg"],
    13: ["Image", "TargetObject", "Details", "EventType_reg"],
    14: ["Image", "TargetObject", "NewName", "EventType_reg"],
    15: ["Image", "TargetFilename", "Hashes"],
    16: ["Image", "Configuration", "Value"],
    17: ["Image", "PipeName", "User"],
    18: ["Image", "PipeName", "User"],
    22: ["Image", "QueryName", "QueryResults", "User"],
    23: ["Image", "TargetFilename", "User"],
    25: ["Image", "TamperingType", "User"],
    26: ["Image", "TargetFilename", "User"],
}

# -- windows_deepsensor (EdrRow) fields ---------------------------------------
_EDR_FIELDS = [
    "Image", "CommandLine", "destination_ip", "pid", "ppid",
    "event_type", "category", "score", "avg_entropy", "max_velocity",
    "tactic", "technique", "severity",
]

# -- linux_sentinel fields -----------------------------------------------------
_LIN_FIELDS = [
    "comm", "command_line", "uid", "dest_ip", "pid", "ppid",
    "target_file", "anomaly_score", "mitre_tactic", "mitre_technique",
]

# -- Cloud fields --------------------------------------------------------------
_AZURE_FIELDS = [
    "user_principal_name", "result_type", "ip_address", "error_code",
    "app_display_name", "operation_name",
]
_AWS_FIELDS = [
    "event_name", "source_ip", "user_identity_type", "error_code",
    "principal_arn", "request_parameters",
]


# -- Sensor field-name alias map -----------------------------------------------
# The live sensor Parquet columns sometimes differ from the canonical field names
# that prompts and training records use.  Apply these aliases before _clean() so
# that payloads arriving from the real sensors produce the same prompt format as
# the synthetic staging records.
#
# Key   = field name emitted by the sensor Parquet schema
# Value = canonical field name expected in prompts / _EDR_FIELDS / _LIN_FIELDS
#
# Source:
#   windows_deepsensor TelemetryRow (transmission/src/parquet.rs):
#     path          → Image          (sensor uses 'path'; prompts use 'Image')
#     command_line  → CommandLine    (sensor uses snake_case; sysmon uses PascalCase)
#     parent_pid    → ppid           (sensor uses full name; pipeline uses short form)
#     event_user    → User           (sensor uses 'event_user'; prompts use 'User')
#
#   linux_c2 FlowEvent (shared_models/telemetry.rs):
#     comm          → process_name   (Rust uses 'comm'; spool script queries 'process_name')
#     dst_ip        → dst_ip         (unchanged — already canonical)
SENSOR_FIELD_ALIASES: dict[str, dict[str, str]] = {
    "windows_deepsensor": {
        "path":         "Image",
        "command_line": "CommandLine",
        "parent_pid":   "ppid",
        "event_user":   "User",
    },
    "linux_c2": {
        "comm": "process_name",
    },
}


def _apply_aliases(payload: dict, sensor: str) -> dict:
    """Rename sensor-emitted field names to canonical names before prompt construction."""
    aliases = SENSOR_FIELD_ALIASES.get(sensor, {})
    if not aliases:
        return payload
    return {aliases.get(k, k): v for k, v in payload.items()}


def _clean(payload: dict, allowed: list) -> dict:
    """Return only non-None values for fields in the allowed list."""
    return {k: v for k, v in payload.items() if k in allowed and v is not None}


# -- Public formatters ---------------------------------------------------------

def fmt_sysmon(host: str, event_id: int, payload: dict) -> str:
    """
    Build a sysmon_sensor user-turn prompt in the canonical inference format.

    payload — dict whose keys are Sysmon XML field names (case-sensitive as
              Sysmon emits them: Image, CommandLine, ParentImage, etc.).
    """
    allowed = SYSMON_EVENT_FIELDS.get(event_id, list(payload.keys()))
    clean = {k: v for k, v in payload.items()
             if k in allowed and v is not None and v != ""}
    clean["sysmon_event_id"] = event_id

    event_name = SYSMON_EVENT_NAMES.get(event_id, f"EventID {event_id}")
    return (
        f"Spatial Anomaly Detected.\n"
        f"Source: sysmon_sensor  Hostname: {host}  "
        f"EventID: {event_id}  ({event_name})\n"
        f"Vector: {SPATIAL_TOKEN}\n"
        f"Raw Payload: {json.dumps(clean, separators=(',', ':'))}"
    )


def fmt_edr(host: str, payload: dict) -> str:
    """
    Build a windows_deepsensor (EdrRow / DeepXDR) user-turn prompt.
    Accepts both canonical field names (Image, CommandLine, ppid) and
    the live sensor's Parquet column names (path, command_line, parent_pid).
    SENSOR_FIELD_ALIASES maps live names → canonical before _clean().
    """
    payload = _apply_aliases(payload, "windows_deepsensor")
    clean = _clean(payload, _EDR_FIELDS)
    return (
        f"Spatial Anomaly Detected.\n"
        f"Source: windows_deepsensor  Hostname: {host}\n"
        f"Vector: {SPATIAL_TOKEN}\n"
        f"Raw Payload: {json.dumps(clean, separators=(',', ':'))}"
    )


def fmt_linux(host: str, payload: dict) -> str:
    """Build a linux_sentinel user-turn prompt."""
    clean = _clean(payload, _LIN_FIELDS)
    return (
        f"Spatial Anomaly Detected.\n"
        f"Source: linux_sentinel  Hostname: {host}\n"
        f"Vector: {SPATIAL_TOKEN}\n"
        f"Raw Payload: {json.dumps(clean, separators=(',', ':'))}"
    )


def fmt_azure(tenant: str, payload: dict) -> str:
    """Build an azure_entraid user-turn prompt."""
    clean = _clean(payload, _AZURE_FIELDS)
    return (
        f"Spatial Anomaly Detected.\n"
        f"Source: azure_entraid  Tenant: {tenant}\n"
        f"Vector: {SPATIAL_TOKEN}\n"
        f"Raw Payload: {json.dumps(clean, separators=(',', ':'))}"
    )


def fmt_aws(account: str, payload: dict) -> str:
    """Build an aws_cloudtrail user-turn prompt."""
    clean = _clean(payload, _AWS_FIELDS)
    return (
        f"Spatial Anomaly Detected.\n"
        f"Source: aws_cloudtrail  Account: {account}\n"
        f"Vector: {SPATIAL_TOKEN}\n"
        f"Raw Payload: {json.dumps(clean, separators=(',', ':'))}"
    )


def fmt_nettap(src_ip: str, dst_ip: str, dst_port: int, payload: dict) -> str:
    """
    Build a network_tap user-turn prompt.
    payload — dict of pre-computed nettap behavioral fields.
    """
    direction = "internal" if payload.get("is_internal_dst") else "external"
    clean = {k: v for k, v in payload.items() if v is not None}
    clean.update({"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port})
    return (
        f"Spatial Anomaly Detected.\n"
        f"Source: network_tap  {src_ip} → {dst_ip}:{dst_port}  ({direction})\n"
        f"Vector: {SPATIAL_TOKEN}\n"
        f"Raw Payload: {json.dumps(clean, separators=(',', ':'))}"
    )

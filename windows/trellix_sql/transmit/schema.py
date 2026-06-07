"""
schema.py -- 6D trellix_math Parquet schema and row construction.

Vector layout (matches nexus.toml / qdrant_init.sh after 6D upgrade):
  [0] severity_score    -- ThreatSeverity 1-5 → [0.2, 1.0]
  [1] threat_score      -- ThreatType malice weight
  [2] action_score      -- ActionTaken response weight
  [3] anomaly_score     -- IsolationForest UEBA score
  [4] entropy_score     -- Shannon entropy of FilePath + ProcessName
  [5] frequency_score   -- inverse novelty of ThreatName + ThreatType combo

Context columns mirror nexus.toml [schema_mappings.trellix_ens] after update.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Optional

import pyarrow as pa

# -- Parquet schema ------------------------------------------------------------

TRELLIX_MATH_SCHEMA = pa.schema([
    # Identity
    pa.field("sensor_id",         pa.string(),    nullable=False),
    pa.field("batch_id",          pa.string(),    nullable=False),
    pa.field("timestamp",         pa.timestamp("us", tz="UTC"), nullable=False),
    pa.field("auto_id",           pa.int64(),     nullable=False),  # EPO AutoID

    # 6D vector (list<float32> -- matches Qdrant named vector trellix_math size=6)
    pa.field("trellix_math",      pa.list_(pa.float32()), nullable=False),

    # Scalar decomposition (stored alongside vector for SQL/audit)
    pa.field("severity_score",    pa.float32(),   nullable=False),
    pa.field("threat_score",      pa.float32(),   nullable=False),
    pa.field("action_score",      pa.float32(),   nullable=False),
    pa.field("anomaly_score",     pa.float32(),   nullable=False),
    pa.field("entropy_score",     pa.float32(),   nullable=False),
    pa.field("frequency_score",   pa.float32(),   nullable=False),

    # Context columns (nexus.toml context_columns -- mapped from ePO canonical column names)
    pa.field("host",                      pa.string(),    nullable=True),
    pa.field("process",                   pa.string(),    nullable=True),
    pa.field("pid",                       pa.int32(),     nullable=True),
    pa.field("user",                      pa.string(),    nullable=True),
    pa.field("file_path",                 pa.string(),    nullable=True),  # ← ThreatFileName in SQL
    pa.field("file_name",                 pa.string(),    nullable=True),  # basename of ThreatFileName
    pa.field("threat_source_url",         pa.string(),    nullable=True),  # ← ThreatSourceUrl in SQL
    pa.field("detection_name",            pa.string(),    nullable=True),
    pa.field("threat_type",               pa.string(),    nullable=True),
    pa.field("action",                    pa.string(),    nullable=True),
    pa.field("severity",                  pa.int32(),     nullable=True),
    pa.field("message",                   pa.string(),    nullable=True),
    pa.field("threat_category",           pa.string(),    nullable=True),
    pa.field("event_id",                  pa.int32(),     nullable=True),  # ← ThreatEventID in SQL
    pa.field("source_component",          pa.string(),    nullable=True),  # AnalyzerName
    pa.field("analyzer_detection_method", pa.string(),    nullable=True),  # ← AnalyzerDetectionMethod

    # Stream classification
    pa.field("stream",            pa.string(),    nullable=False),  # 'ens' | 'appcontrol'
])


# -- Threat-type score table ---------------------------------------------------

_THREAT_SCORE: dict[str, float] = {
    "trojan":           1.00,
    "exploit":          0.95,
    "ransomware":       1.00,
    "backdoor":         0.95,
    "rootkit":          0.95,
    "apt":              1.00,
    "malware":          0.85,
    "suspicious":       0.70,
    "pua":              0.40,
    "adware":           0.20,
    "riskware":         0.30,
    "clean":            0.00,
    "solidcore":        0.60,   # AppControl block
    "application control": 0.55,
}


def threat_type_to_score(threat_type: Optional[str]) -> float:
    if not threat_type:
        return 0.5
    key = threat_type.lower()
    for k, v in _THREAT_SCORE.items():
        if k in key:
            return v
    return 0.5


def build_row(
    auto_id: int,
    received_utc: datetime.datetime,
    agent_guid: Optional[str],
    source_host: Optional[str],
    threat_name: Optional[str],
    threat_type: Optional[str],
    threat_category: Optional[str],
    threat_severity: Optional[int],
    action_taken: Optional[str],
    user_name: Optional[str],
    threat_file_name: Optional[str],     # SQL: ThreatFileName
    threat_source_url: Optional[str],    # SQL: ThreatSourceUrl
    process_name: Optional[str],
    threat_event_id: Optional[int],      # SQL: ThreatEventID
    analyzer_name: Optional[str],
    analyzer_detection_method: Optional[str],  # SQL: AnalyzerDetectionMethod
    # UEBA outputs
    anomaly_score: float,
    entropy_score: float,
    frequency_score: float,
    # Batch metadata
    batch_id: str,
    stream: str,
    # Pre-computed scores from ueba_engine helpers
    severity_score: float,
    threat_score: float,
    action_score: float,
) -> dict[str, Any]:
    """Build a single Parquet row dict matching TRELLIX_MATH_SCHEMA."""

    vector = [
        float(severity_score),
        float(threat_score),
        float(action_score),
        float(anomaly_score),
        float(entropy_score),
        float(frequency_score),
    ]

    return {
        "sensor_id":                  agent_guid or source_host or "unknown",
        "batch_id":                   batch_id,
        "timestamp":                  received_utc.replace(tzinfo=datetime.timezone.utc)
                                      if received_utc.tzinfo is None else received_utc,
        "auto_id":                    auto_id,
        "trellix_math":               vector,
        "severity_score":             float(severity_score),
        "threat_score":               float(threat_score),
        "action_score":               float(action_score),
        "anomaly_score":              float(anomaly_score),
        "entropy_score":              float(entropy_score),
        "frequency_score":            float(frequency_score),
        "host":                       source_host,
        "process":                    process_name,
        "pid":                        None,
        "user":                       user_name,
        "file_path":                  threat_file_name,          # nexus name for ThreatFileName
        "file_name":                  _basename(threat_file_name),
        "threat_source_url":          threat_source_url,
        "detection_name":             threat_name,
        "threat_type":                threat_type,
        "action":                     action_taken,
        "severity":                   threat_severity,
        "message":                    None,
        "threat_category":            threat_category,
        "event_id":                   threat_event_id,           # nexus name for ThreatEventID
        "source_component":           analyzer_name,
        "analyzer_detection_method":  analyzer_detection_method,
        "stream":                     stream,
    }


def make_batch_id() -> str:
    return str(uuid.uuid4())


def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    sep = "\\" if "\\" in path else "/"
    return path.rstrip(sep).rsplit(sep, 1)[-1] or None

"""
BeaconML.py -- Windows C2 Sensor: WFP flow-stat field computation
WS-1: Compute 7 flow-stat fields from Windows Filtering Platform captures
       before writing records to c2_ledger_queue.

Mirrors linux/c2_sensor/python_engine/BeaconML.py for the Windows WFP path.

Fields computed (c2_math 8D vector):
  [0] outbound_ratio      -- outbound / (inbound + outbound) bytes
  [1] packet_size_mean    -- mean packet size in bytes
  [2] packet_size_std     -- std dev of packet size
  [3] interval            -- mean inter-packet interval (seconds)
  [4] cv                  -- coefficient of variation of intervals
  [5] entropy             -- Shannon entropy of payload bytes (0-8 bits)
  [6] cmd_entropy         -- Shannon entropy of command / query string
  [7] score               -- BeaconML confidence score (0-100)

Usage (called by C2Sensor Rust process via subprocess or COM bridge):

    from BeaconML import compute_flow_stats, detect_beaconing_wfp

    stats = compute_flow_stats(
        packets=[{"ts": 1.0, "size": 128, "direction": "out", "payload_bytes": b"..."},...],
        query_string="GET /c2/checkin HTTP/1.1",
    )
    # stats is a FlowStats namedtuple with all 8 fields

STATUS: WS-1 COMPLETE -- FlowStats are computed natively in Rust by
        ml_engine/src/lib.rs (BehavioralEngine::evaluate_flow, both fast-path
        and volumetric) and injected directly into the JSON alert payload sent
        to TransmissionLayer via MPSC.  No pyo3 bridge needed.
        This file serves as the Python reference/test implementation and as the
        subprocess fallback for the PowerShell C# orchestration path.
"""

from __future__ import annotations

import math
import statistics
from typing import List, Dict, Any, NamedTuple


class FlowStats(NamedTuple):
    outbound_ratio: float    # [0]
    packet_size_mean: float  # [1]
    packet_size_std: float   # [2]
    interval: float          # [3] mean inter-packet interval (s)
    cv: float                # [4] coefficient of variation of intervals
    entropy: float           # [5] payload byte entropy
    cmd_entropy: float       # [6] command/query string entropy
    score: float             # [7] BeaconML confidence 0-100


_SAFE_ZERO = FlowStats(
    outbound_ratio=0.75, packet_size_mean=0.0, packet_size_std=0.0,
    interval=0.0, cv=0.0, entropy=0.0, cmd_entropy=0.0, score=0.0,
)


# -- Entropy helpers ------------------------------------------------------------

def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _string_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# -- Core computation -----------------------------------------------------------

def compute_flow_stats(
    packets: List[Dict[str, Any]],
    query_string: str = "",
) -> FlowStats:
    """Derive 8D c2_math vector fields from a list of WFP packet captures.

    Each packet dict must contain:
      ts        (float)  -- epoch timestamp in seconds
      size      (int)    -- total packet size in bytes
      direction (str)    -- "out" | "in"
      payload_bytes (bytes, optional) -- raw payload for entropy

    Returns FlowStats with all 8 fields; falls back to _SAFE_ZERO if fewer
    than 2 packets are provided (insufficient data).
    """
    if len(packets) < 2:
        return _SAFE_ZERO

    sizes = [float(p["size"]) for p in packets]
    outbound = sum(p["size"] for p in packets if p.get("direction") == "out")
    total_bytes = sum(p["size"] for p in packets)
    outbound_ratio = outbound / total_bytes if total_bytes > 0 else 0.75

    packet_size_mean = statistics.mean(sizes)
    packet_size_std = statistics.pstdev(sizes)

    # Inter-packet intervals (sorted timestamps)
    timestamps = sorted(p["ts"] for p in packets)
    intervals = [timestamps[i + 1] - timestamps[i]
                 for i in range(len(timestamps) - 1)
                 if timestamps[i + 1] > timestamps[i]]

    if intervals:
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.pstdev(intervals)
        cv = std_interval / mean_interval if mean_interval > 0 else 0.0
    else:
        mean_interval = 0.0
        cv = 0.0

    # Payload entropy: average over all packets that have payload_bytes
    payload_entropies = [
        _byte_entropy(p["payload_bytes"])
        for p in packets
        if p.get("payload_bytes")
    ]
    entropy = statistics.mean(payload_entropies) if payload_entropies else 0.0
    cmd_entropy = _string_entropy(query_string)

    # Beacon score: mirrors BeaconML fast-path heuristic
    score = _beacon_score(cv, mean_interval, packet_size_std, entropy)

    return FlowStats(
        outbound_ratio=round(outbound_ratio, 4),
        packet_size_mean=round(packet_size_mean, 4),
        packet_size_std=round(packet_size_std, 4),
        interval=round(mean_interval, 4),
        cv=round(cv, 4),
        entropy=round(entropy, 4),
        cmd_entropy=round(cmd_entropy, 4),
        score=round(score, 2),
    )


def _beacon_score(cv: float, interval: float, size_std: float, entropy: float) -> float:
    """Heuristic beacon confidence (0-100) for pre-ML screening.

    Mirrors the fast-path score in linux BeaconML.detect_beaconing_list.
    Passes to the full ML pipeline when score >= 40.
    """
    if cv > 0.50:
        return 10.0   # organic bursty traffic
    if cv < 0.02 and entropy < 5.0:
        return 0.0    # mechanical sync (NTP, heartbeat)

    score = 0.0
    if cv < 0.15:
        score += 40.0                        # tight timing regularity
    if 5.0 <= interval <= 300.0:
        score += 20.0                        # typical C2 check-in range
    if entropy > 3.0:
        score += 20.0                        # encrypted payload
    if size_std < 50.0:
        score += 15.0                        # consistent packet sizes
    return min(score, 95.0)


# -- WS-1 COMPLETE: Rust-native FlowStats integration -------------------------
#
# ml_engine/src/lib.rs::BehavioralEngine::evaluate_flow computes the same 8D
# vector natively (FlowStats struct, lines ~313-329) and injects it into the
# serde_json alert payload sent over the MPSC channel to TransmissionLayer,
# which writes all 7 columns to c2_ledger_queue (transmission/src/lib.rs).
#
# This file provides:
#   • Python reference implementation (field formulae authoritative)
#   • Subprocess entry point for PowerShell/C# orchestration path
#   • Test fixture for cross-validating Rust vs Python values
#
# ------------------------------------------------------------------------------


def detect_beaconing_wfp(
    packets: List[Dict[str, Any]],
    query_string: str = "",
    score_threshold: float = 40.0,
) -> tuple[FlowStats, bool, str]:
    """High-level entry point: compute stats and classify as beacon or not.

    Returns (FlowStats, is_beacon: bool, reason: str).
    """
    stats = compute_flow_stats(packets, query_string)
    if stats.score >= score_threshold:
        reason = (
            f"cv={stats.cv:.3f} interval={stats.interval:.1f}s "
            f"entropy={stats.entropy:.2f} score={stats.score:.0f}"
        )
        return stats, True, f"Beaconing candidate: {reason}"
    return stats, False, f"Below threshold (score={stats.score:.0f})"

"""
Confidence-calibration ledger (NC-2; NIST MS-2.13-001).

Closes the loop on the swarm's `confidence` field: when an operator dispositions an
investigation (via worker_rlhf / SOAR callback), the predicted verdict+confidence is
paired with the realized outcome (`agents.controls.calibration_record`) and appended
to a JSONL ledger. `brier_trend` rolls the ledger up into a calibration health
signal (mean Brier score, accuracy, and an over/under-confidence indicator) that the
MLOps maturation metric plane and the deploy gate can read.

Pure + file-append only; no service dependency.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import List, Dict, Any

from agents.controls import calibration_record, over_reliance_report, reliance_record

DEFAULT_LEDGER = os.getenv("NEXUS_CALIBRATION_LEDGER", "/var/lib/nexus/calibration_v1.jsonl")
DEFAULT_RELIANCE_LEDGER = os.getenv("NEXUS_RELIANCE_LEDGER", "/var/lib/nexus/reliance_v1.jsonl")


def record_disposition(verdict: dict, operator_disposition: str, event_id: str = "",
                       ledger_path: str = DEFAULT_LEDGER) -> dict:
    """Append one calibration data point pairing the swarm's prediction with the
    operator's realized disposition. Returns the record."""
    rec = calibration_record(verdict, operator_disposition)
    rec["event_id"] = event_id
    rec["ts"] = time.time()
    p = Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


# -- NC-7 automation-bias / over-reliance (NIST MG-1.3-002, MP-3.4-005) -------
# Same operator-disposition feedback loop, measured from the *human* side: did the
# operator accept or override the verdict, and (once ground truth is known) how
# often was a wrong AI call rubber-stamped. Shares load_ledger; separate ledger.

def record_reliance(verdict: dict, operator_action: str,
                    ground_truth_disposition=None, event_id: str = "",
                    ledger_path: str = DEFAULT_RELIANCE_LEDGER) -> dict:
    """Append one human-AI reliance data point (accept vs override + ground truth)."""
    rec = reliance_record(verdict, operator_action, ground_truth_disposition)
    rec["event_id"] = event_id
    rec["ts"] = time.time()
    p = Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def over_reliance(records, high_conf: float = 0.8, min_support: int = 5,
                  max_automation_bias: float = 0.5) -> dict:
    """Automation-bias / over-reliance health over reliance records."""
    return over_reliance_report(records, high_conf, min_support, max_automation_bias)


def load_ledger(ledger_path: str = DEFAULT_LEDGER) -> List[Dict[str, Any]]:
    p = Path(ledger_path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def brier_trend(records: List[Dict[str, Any]], last_n: int = 0) -> dict:
    """Calibration health over the (optionally last_n) records.

    `mean_brier` lower is better-calibrated. `over_confidence` > 0 means the swarm
    is systematically more confident than warranted (its mistakes carry high
    confidence); < 0 means under-confident.
    """
    recs = records[-last_n:] if last_n else list(records)
    n = len(recs)
    if n == 0:
        return {"n": 0, "mean_brier": None, "accuracy": None, "over_confidence": None}
    mean_brier = sum(r.get("brier", 0.0) for r in recs) / n
    accuracy = sum(1 for r in recs if r.get("correct")) / n
    # over-confidence: mean predicted_confidence on WRONG calls minus on RIGHT calls.
    wrong = [r["predicted_confidence"] for r in recs if not r.get("correct")
             and "predicted_confidence" in r]
    right = [r["predicted_confidence"] for r in recs if r.get("correct")
             and "predicted_confidence" in r]
    over = ((sum(wrong) / len(wrong)) - (sum(right) / len(right))) \
        if wrong and right else 0.0
    return {
        "n": n,
        "mean_brier": round(mean_brier, 4),
        "accuracy": round(accuracy, 4),
        "over_confidence": round(over, 4),
    }

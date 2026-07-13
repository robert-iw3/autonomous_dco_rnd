"""
Active-learning failure capture (NC-8; NIST MG-4.1-004, Risk 2.2 Confabulation).

When the swarm is wrong (operator ground truth contradicts the verdict) or cites
ungrounded evidence, capture a structured hard example into a JSONL corpus that the
MLOps continuous-improvement plane consumes (Track-N SFT / hard negatives). The
failure decision + record shape are the pure logic in `agents.controls`; this adds
the durable append. Pure + file-append only; no service dependency.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.controls import failure_record

DEFAULT_CORPUS = os.getenv("NEXUS_FAILURE_CORPUS", "/var/lib/nexus/active_learning_v1.jsonl")


def capture(verdict: dict, operator_disposition: Optional[str] = None,
            grounding_violation: bool = False, event_id: str = "",
            artifacts=None, corpus_path: str = DEFAULT_CORPUS) -> Optional[dict]:
    """Append a hard-example record if this verdict was a failure; else no-op.
    Returns the written record (with `ts`) or None."""
    rec = failure_record(verdict, operator_disposition, grounding_violation, event_id, artifacts)
    if rec is None:
        return None
    rec["ts"] = time.time()
    p = Path(corpus_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def load_corpus(path: str = DEFAULT_CORPUS) -> List[Dict[str, Any]]:
    p = Path(path)
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

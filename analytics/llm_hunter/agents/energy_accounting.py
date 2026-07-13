"""
Per-run inference energy accounting (NC-10; NIST MS-2.12-003, Risk 2.5).

Folds the one-time environmental footprint estimate (NC-6,
governance/environmental_impact_estimate.md) into a per-run measurement the MLOps
metric plane can roll up: each investigation/serving run logs an energy (Wh) +
carbon (gCO2e) estimate via `agents.controls.estimate_inference_energy`. Pure +
file-append only.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

from agents.controls import estimate_inference_energy

DEFAULT_LEDGER = os.getenv("NEXUS_ENERGY_LEDGER", "/var/lib/nexus/energy_v1.jsonl")


def record_run(duration_s, avg_power_w, event_id: str = "", pue: float = 1.5,
               grid_gco2_per_kwh: float = 400.0,
               ledger_path: str = DEFAULT_LEDGER) -> dict:
    """Estimate + append one run's energy/carbon. Returns the record."""
    rec = estimate_inference_energy(duration_s, avg_power_w, pue, grid_gco2_per_kwh)
    rec["event_id"] = event_id
    rec["ts"] = time.time()
    p = Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


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


def totals(records: List[Dict[str, Any]]) -> dict:
    """Sum energy (Wh) + carbon (gCO2e) across runs."""
    recs = list(records or [])
    if not recs:
        return {"n": 0, "energy_wh": 0.0, "co2e_g": 0.0}
    return {
        "n": len(recs),
        "energy_wh": round(sum(float(r.get("energy_wh", 0.0)) for r in recs), 6),
        "co2e_g": round(sum(float(r.get("co2e_g", 0.0)) for r in recs), 6),
    }

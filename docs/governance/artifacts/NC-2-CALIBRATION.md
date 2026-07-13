# NC-2-CALIBRATION — Confidence-calibration ledger

*Implementation: `analytics/llm_hunter/agents/calibration_ledger.py`*

**Execution chain:** Logic → Execution → Effect

**1. Logic** — Pure calibration point: the verdict's predicted confidence vs the operator's realized disposition, scored by Brier error.

`analytics/llm_hunter/agents/controls.py:L119-L133`

```python
def calibration_record(verdict: dict, operator_disposition: str) -> dict:
    """Build one calibration data point. `brier` is the squared error of the
    predicted probability of the realized class (lower is better-calibrated)."""
    v = verdict or {}
    predicted_tp = bool(v.get("is_true_positive"))
    confidence = float(v.get("confidence", 0.0) or 0.0)
    realized_tp = str(operator_disposition).strip().lower() in _REALIZED_TP
    p_tp = confidence if predicted_tp else (1.0 - confidence)
    actual = 1.0 if realized_tp else 0.0
    return {
        "predicted_tp": predicted_tp,
        "predicted_confidence": confidence,
        "realized_tp": realized_tp,
        "correct": predicted_tp == realized_tp,
        "brier": (p_tp - actual) ** 2,
```

**2. Execution** — Each operator disposition is appended to a durable calibration ledger.

`analytics/llm_hunter/agents/calibration_ledger.py:L27-L39`

```python
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

```

**3. Effect** — The Brier-score trend is computed over the ledger so miscalibration is measurable and trackable over time.

`analytics/llm_hunter/agents/calibration_ledger.py:L81-L103`

```python
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
```

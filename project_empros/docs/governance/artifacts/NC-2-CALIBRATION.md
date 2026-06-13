# NC-2-CALIBRATION — Confidence-calibration ledger

*Implementation: `analytics/llm_hunter/agents/calibration_ledger.py`*

Each verdict's stated confidence is recorded against the operator's ground-truth disposition…

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

…and the Brier-score trend is computed so miscalibration is measurable and trackable over time.

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

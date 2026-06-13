# NC-8-OVER-RELIANCE — Automation-bias / over-reliance measurement

*Implementation: `analytics/llm_hunter/agents/calibration_ledger.py`*

Measures the human side of HitL: automation_bias = P(operator accepted | the AI was wrong) — the share of the swarm's mistakes a human rubber-stamped — split by AI-confidence band.

`analytics/llm_hunter/agents/controls.py:L370-L392`

```python
def over_reliance_report(records, high_conf: float = 0.8, min_support: int = 5,
                         max_automation_bias: float = 0.5) -> dict:
    """Automation-bias / over-reliance metrics over reliance records.

    `automation_bias` = P(operator accepted | AI was wrong) -- the share of the
    swarm's mistakes the human rubber-stamped (only defined where ground truth
    exists). `caught_rate` = P(override | AI wrong). Acceptance is also split by AI
    confidence band as a complementary automation-bias signal. A run is flagged
    when automation_bias exceeds `max_automation_bias` with enough wrong-call
    support.
    """
    recs = list(records or [])
    n = len(recs)
    base = {"n": n, "accept_rate": None, "override_rate": None,
            "accept_rate_high_conf": None, "accept_rate_low_conf": None,
            "n_ai_wrong": 0, "n_ai_correct": 0, "automation_bias": None,
            "caught_rate": None, "over_distrust": None, "flagged": False, "reasons": []}
    if n == 0:
        return base

    accepts = sum(1 for r in recs if r.get("accepted"))
    base["accept_rate"] = round(accepts / n, 4)
    base["override_rate"] = round((n - accepts) / n, 4)
```

Each operator decision is logged as an accept-vs-override reliance point against the eventual ground truth.

`analytics/llm_hunter/agents/calibration_ledger.py:L46-L56`

```python
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
```

# NC-9-ACTIVE-LEARNING — Active-learning failure capture

*Implementation: `analytics/llm_hunter/agents/active_learning.py`*

**Execution chain:** Invocation → Logic → Logic → Execution

**1. Invocation** — Wired into the terminal node: on every run a confabulated (grounding-violated) verdict is handed to the capture path (fail-soft).

`analytics/llm_hunter/agents/response.py:L193-L198`

```python
        if grounding_violations:
            active_learning.capture(
                verdict, grounding_violation=True, event_id=event_id,
                artifacts=list(grounding_violations),
                corpus_path=os.getenv("NEXUS_FAILURE_CORPUS", active_learning.DEFAULT_CORPUS),
            )
```

**2. Logic** — A verdict is a captured failure when it cites ungrounded evidence or its class contradicts operator ground truth.

`analytics/llm_hunter/agents/controls.py:L429-L438`

```python
def is_model_failure(verdict: dict, ground_truth_disposition=None,
                     grounding_violation: bool = False) -> bool:
    """True if this verdict is a captured failure: an ungrounded citation, or a
    class mismatch against operator ground truth (when ground truth is known)."""
    if grounding_violation:
        return True
    if ground_truth_disposition is None:
        return False
    truth_tp = str(ground_truth_disposition).strip().lower() in _REALIZED_TP
    return bool((verdict or {}).get("is_true_positive")) != truth_tp
```

**3. Logic** — Builds the structured hard-example record (predicted vs realized, reason, artifacts) — or None for a correct verdict.

`analytics/llm_hunter/agents/controls.py:L441-L455`

```python
def failure_record(verdict: dict, ground_truth_disposition=None,
                   grounding_violation: bool = False, event_id: str = "",
                   artifacts=None) -> dict | None:
    """Structured hard-example record, or None if the verdict was not a failure."""
    if not is_model_failure(verdict, ground_truth_disposition, grounding_violation):
        return None
    v = verdict or {}
    realized = None
    if ground_truth_disposition is not None:
        realized = str(ground_truth_disposition).strip().lower() in _REALIZED_TP
    return {
        "event_id": event_id,
        "predicted_tp": bool(v.get("is_true_positive")),
        "predicted_confidence": float(v.get("confidence", 0.0) or 0.0),
        "realized_tp": realized,
```

**4. Execution** — Appends the failure to the hard-example corpus the MLOps plane consumes; a correct verdict is a no-op.

`analytics/llm_hunter/agents/active_learning.py:L23-L35`

```python
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
```

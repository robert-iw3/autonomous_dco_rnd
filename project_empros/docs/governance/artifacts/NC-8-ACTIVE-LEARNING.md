# NC-8-ACTIVE-LEARNING — Active-learning failure capture

*Implementation: `analytics/llm_hunter/agents/active_learning.py`*

A verdict is a captured failure when it cites ungrounded evidence or its class contradicts operator ground truth.

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

Failures are appended to a hard-example corpus the MLOps plane consumes for continuous improvement; correct verdicts are a no-op.

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

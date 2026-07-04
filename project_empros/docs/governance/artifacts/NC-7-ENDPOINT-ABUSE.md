# NC-7-ENDPOINT-ABUSE — Inference-endpoint abuse / model-extraction monitoring

*Implementation: `analytics/llm_hunter/agents/endpoint_abuse_monitor.py`*

**Execution chain:** Logic → Logic → Logic → Execution

**1. Logic** — Per-caller volume spike over the caller's own baseline (or an absolute floor for a cold-start abuser) -- the model-extraction volume signal.

`analytics/llm_hunter/agents/controls.py:L519-L531`

```python
def query_volume_anomalies(current, baseline, factor: float = 3.0,
                           min_floor: int = 100) -> list:
    """Callers whose current-window volume exceeds max(baseline*factor, floor).

    A caller with no baseline (brand new) is gated by the absolute floor only, so
    a cold-start abuser is still caught without flagging normal ramp-up."""
    baseline = baseline or {}
    out = []
    for caller, n in (current or {}).items():
        base = float(baseline.get(caller, 0.0))
        threshold = base * factor + min_floor if base else float(min_floor)
        if n > threshold:
            out.append({"caller": caller, "count": n, "baseline": base,
```

**2. Logic** — Systematic near-duplicate probing: mean pairwise token-set Jaccard flags a caller sweeping perturbed prompts to map the decision boundary.

`analytics/llm_hunter/agents/controls.py:L547-L565`

```python
def membership_inference_signal(queries, sim_threshold: float = 0.85,
                                min_queries: int = 10, sample_cap: int = 200) -> dict:
    """Flag systematic probing: a caller issuing many mutually-similar queries.

    Model-extraction / membership-inference campaigns sweep near-duplicate prompts
    (perturbing an id, an IP, a score) to map the decision boundary. Mean pairwise
    token-set Jaccard over the caller's queries captures that without embeddings.
    Below min_queries there is not enough signal to judge."""
    qs = [q for q in (queries or []) if str(q).strip()]
    n = len(qs)
    if n < min_queries:
        return {"flagged": False, "mean_similarity": 0.0, "n": n}
    sets = [_token_set(q) for q in qs[:sample_cap]]
    m = len(sets)
    total, pairs = 0.0, 0
    for i in range(m):
        for j in range(i + 1, m):
            total += _jaccard(sets[i], sets[j])
            pairs += 1
```

**3. Logic** — Combines quota, volume, and probing signals into a per-caller verdict with the tripped axes, for operator throttle/revoke.

`analytics/llm_hunter/agents/controls.py:L571-L587`

```python
def endpoint_abuse_report(records, quota: int = 1000, baseline=None,
                          volume_factor: float = 3.0, volume_floor: int = 100,
                          sim_threshold: float = 0.85, min_queries: int = 10) -> dict:
    """Per-caller abuse verdict over access records [{caller, query}].

    Combines the three signals; a caller is flagged with the axes that tripped so
    an operator sees why. No single axis is dispositive on its own -- the report
    surfaces them, the steward/operator decides on throttle vs revoke."""
    by_caller = {}
    for r in records or []:
        by_caller.setdefault(str((r or {}).get("caller", "")), []).append(
            str((r or {}).get("query", "")))
    counts = {c: len(q) for c, q in by_caller.items()}
    over_quota = dict(per_caller_quota_exceeded(counts, quota))
    vol = {a["caller"]: a for a in query_volume_anomalies(
        counts, baseline or {}, volume_factor, volume_floor)}
    flagged = []
```

**4. Execution** — Scheduler entry point: pulls the sovereign vLLM access log, runs the abuse audit against the prior-window baseline, and writes a dated report.

`analytics/llm_hunter/agents/endpoint_abuse_monitor.py:L120-L126`

```python
def collect_and_monitor(client=None, source: str = "", limit: int = 500000,
                        report_dir: str = DEFAULT_REPORT_DIR,
                        collector: Optional[Callable] = None,
                        baseline: Optional[dict] = None, **audit_kwargs) -> dict:
    """Scheduler entry point: collect access records, run the abuse audit, write the
    report. `collector(client, source, limit) -> records` and `baseline` may be
    injected (tests); otherwise the baseline is read from the last report. Extra
```

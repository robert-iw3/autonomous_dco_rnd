# NC-1-BIAS-AUDIT — Bias/disparity + homogenization scheduled audit

*Implementation: `analytics/llm_hunter/agents/bias_audit.py`*

**Execution chain:** Logic → Logic → Execution

**1. Logic** — Pure disaggregated disparity analytic: per-subgroup containment/TP rates vs the fleet baseline, flagging any group beyond the disparity tolerance.

`analytics/llm_hunter/agents/controls.py:L239-L249`

```python
def fairness_report(records, dimension: str = "source_type",
                    min_support: int = 5, max_disparity: float = 0.2) -> dict:
    """Disaggregated fairness audit over historical verdict records.

    Each record is a dict carrying the grouping `dimension` plus either an
    `action` string or a `contained` bool, and (optionally) `is_true_positive`.
    A subgroup with at least `min_support` samples whose containment rate differs
    from the overall baseline by more than `max_disparity` (absolute) is flagged.
    """
    records = list(records or [])
    total = len(records)
```

**2. Logic** — Pure model-collapse monitor: flags when the immunity store over-concentrates on one signature (top-share / low entropy).

`analytics/llm_hunter/agents/controls.py:L301-L313`

```python
def memory_homogenization(signatures, top_share_threshold: float = 0.5,
                          min_entropy: float = 0.5) -> dict:
    """Distribution health of the immunity memory. Accepts a list of signatures
    or a {signature: count} mapping. Flags `homogenized` when one signature owns
    more than `top_share_threshold` of the memory, or normalized Shannon entropy
    drops below `min_entropy`."""
    if isinstance(signatures, dict):
        counts = {k: int(v) for k, v in signatures.items() if int(v) > 0}
    else:
        counts = {}
        for s in (signatures or []):
            counts[s] = counts.get(s, 0) + 1

```

**3. Execution** — The scheduled audit job runs both analytics over the verdict/immunity history and writes a flagged report.

`analytics/llm_hunter/agents/bias_audit.py:L41-L63`

```python
def run_bias_audit(records: List[Dict[str, Any]], dimension: str = "source_type",
                   min_support: int = 5, max_disparity: float = 0.2) -> dict:
    """Pure: turn a list of verdict-memory records into a fairness + homogenization
    audit. Each record carries `source_type`, `is_true_positive`, an `action`
    (or `contained`), and `vector_name`."""
    fair = fairness_report(records, dimension=dimension,
                           min_support=min_support, max_disparity=max_disparity)
    homo = memory_homogenization([_signature(r) for r in records])
    flagged_reasons = []
    if fair["flagged"]:
        flagged_reasons.append(f"containment disparity in {fair['flagged']}")
    if homo["homogenized"]:
        flagged_reasons.append(
            f"immunity-memory over-concentration (top_share={homo['top_share']})")
    return {
        "generated_at": time.time(),
        "n_records": len(records),
        "dimension": dimension,
        "fairness": fair,
        "homogenization": homo,
        "flagged": bool(flagged_reasons),
        "flagged_reasons": flagged_reasons,
    }
```

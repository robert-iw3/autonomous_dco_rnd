# NC-1-BIAS-AUDIT — Bias/disparity + homogenization scheduled audit

*Implementation: `analytics/llm_hunter/agents/bias_audit.py`*

Scheduled audit computes per-dimension disparity and memory-homogenization metrics over the immunity store to detect bias/monoculture drift.

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

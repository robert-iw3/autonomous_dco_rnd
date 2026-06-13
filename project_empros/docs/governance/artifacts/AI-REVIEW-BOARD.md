# AI-REVIEW-BOARD — Adversarial review board (per-expert counterparts)

*Implementation: `analytics/llm_hunter/agents/review_board.py`*

Adversarial board aggregation is a pure, deterministic decision rule over per-expert counterpart rebuttals — no model can unilaterally confirm a verdict.

`analytics/llm_hunter/agents/review_board.py:L189-L217`

```python
def aggregate_board(supervisor_verdict: dict, rebuttals: list) -> dict:
    """PURE decision rule. A TP survives only if every implicated counterpart RAN
    and FAILED to disprove. Any disproof overrides; any unreviewable implicated
    domain fails closed to monitor."""
    sv = supervisor_verdict or {}
    sv_tp = bool(sv.get("is_true_positive"))
    sv_conf = float(sv.get("confidence", 0.0) or 0.0)

    implicated = [r for r in rebuttals if getattr(r, "implicated", False)]
    disprovers = [r for r in implicated if getattr(r, "disproved", False)
                  and "UNREVIEWABLE" not in (getattr(r, "justification", "") or "")]
    unreviewable = [r for r in implicated
                    if "UNREVIEWABLE" in (getattr(r, "justification", "") or "")]

    def summary():
        parts = []
        for r in rebuttals:
            if not getattr(r, "implicated", False):
                continue
            tag = "DISPROVED" if r in disprovers else ("UNREVIEWABLE" if r in unreviewable else "upheld")
            parts.append(f"{r.domain}:{tag}")
        return ", ".join(parts) if parts else "no domain implicated"

    # -- True-positive under review -------------------------------------------
    if sv_tp:
        if not implicated:
            return _verdict(False, 0.0, "monitor",
                            f"Review board: supervisor TP had no implicated domain to adversarially "
                            f"review -- failing closed. [{summary()}]")
```

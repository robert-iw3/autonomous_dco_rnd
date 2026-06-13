# AI-REVIEW-BOARD — Adversarial review board (per-expert counterparts)

*Implementation: `analytics/llm_hunter/agents/review_board.py`*

**Execution chain:** Invocation → Node → Logic

**1. Invocation** — The board is wired into the graph as a mandatory node on the path to any response.

`analytics/llm_hunter/orchestrator.py:L136-L136`

```python
    builder.add_node("review_board", review_board_node)
```

**2. Node** — The node runs every implicated expert's counterpart concurrently against the supervisor verdict.

`analytics/llm_hunter/agents/review_board.py:L266-L275`

```python
async def review_board_node(state: InvestigativeState):
    """Run every counterpart against the supervisor's verdict and aggregate."""
    verdict = state.get("verdict") or {}
    logger.info("Review board convening: %d counterparts vs supervisor verdict (tp=%s)",
                len(COUNTERPARTS), verdict.get("is_true_positive"))

    rebuttals = await asyncio.gather(
        *[_run_counterpart(domain, state, verdict) for domain in COUNTERPARTS],
        return_exceptions=False,
    )
```

**3. Logic** — A pure, deterministic decision rule aggregates the rebuttals: a TP survives only if no implicated counterpart can disprove it — no model unilaterally confirms a verdict. Fails closed.

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

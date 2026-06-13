# AI-GROUNDING — Confabulated-evidence grounding

*Implementation: `analytics/llm_hunter/agents/controls.py`*

Every cited artifact in a verdict must trace to the assembled evidence corpus; ungrounded (confabulated) claims are flagged and the verdict is demoted.

`analytics/llm_hunter/agents/controls.py:L82-L112`

```python
def enforce_grounding(board_result: dict, state: dict):
    """If the board CONFIRMED a TP but the supervisor's finding cited artifacts the
    swarm never retrieved, demote to `monitor` (fail-closed). Returns
    (possibly-overridden result, violations)."""
    board_result = board_result or {}
    if not (board_result.get("verdict") or {}).get("is_true_positive"):
        return board_result, []
    supervisor_verdict = state.get("verdict") or {}
    violations = grounding_violations(supervisor_verdict, build_evidence_corpus(state))
    if not violations:
        return board_result, []
    prior = (board_result.get("verdict") or {}).get("justification", "")
    demoted = dict(board_result)
    demoted["verdict"] = {
        "is_true_positive": False,
        "confidence": 0.0,
        "recommended_action": "monitor",
        "justification": (
            "GROUNDING OVERRIDE: confirmed TP cited artifacts not found in the "
            f"investigation evidence ({', '.join(violations)}) -- treated as "
            f"confabulation; failing closed to monitor. {prior}"
        )[:1000],
    }
    return demoted, violations


# ---------------------------------------------------------------------------
# P3 -- Confidence calibration logging (NIST MS-2.13-001)
# Pairs the swarm's predicted verdict/confidence with the operator's realized
# disposition so calibration (and over/under-confidence) can be measured.
# ---------------------------------------------------------------------------
```

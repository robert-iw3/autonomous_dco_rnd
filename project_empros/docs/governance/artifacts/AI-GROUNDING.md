# AI-GROUNDING — Confabulated-evidence grounding

*Implementation: `analytics/llm_hunter/agents/controls.py`*

**Execution chain:** Logic → Logic → Execution

**1. Logic** — Assembles the ground-truth corpus — the union of every artifact the investigation actually observed (entities, message contents, raw alert).

`analytics/llm_hunter/agents/controls.py:L58-L74`

```python
def build_evidence_corpus(state: dict) -> set:
    """Union of every artifact the investigation actually observed: entity ids +
    notes, message contents, and the raw alert. This is the ground truth a
    confirmed verdict's citations must resolve against."""
    state = state or {}
    corpus: set = set()
    for eid, edata in (state.get("entities_of_interest", {}) or {}).items():
        corpus.add(str(eid))
        corpus |= extract_artifacts(eid)
        corpus |= extract_artifacts((edata or {}).get("notes", ""))
    for m in state.get("messages", []) or []:
        corpus |= extract_artifacts(getattr(m, "content", "") or "")
    alert = state.get("alert", {}) or {}
    corpus |= extract_artifacts(alert.get("raw_event", ""))
    if alert.get("sensor_id"):
        corpus.add(str(alert["sensor_id"]))
    return {c for c in corpus if c}
```

**2. Logic** — Every artifact cited in a confirmed verdict must resolve to that corpus; an ungrounded (confabulated) citation fails the verdict closed to monitor.

`analytics/llm_hunter/agents/controls.py:L84-L114`

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

**3. Execution** — Wired into the live board node: the aggregated verdict is re-grounded, an ungrounded TP is demoted, and the violations are surfaced into state to feed active-learning (NC-9).

`analytics/llm_hunter/agents/review_board.py:L279-L289`

```python
    # Confabulated-evidence grounding (NIST MS-2.5-003): a CONFIRMED TP whose
    # finding cites artifacts the swarm never retrieved is a fabrication -- fail
    # it closed to monitor rather than autonomously containing on phantom evidence.
    result, violations = enforce_grounding(result, state)
    if violations:
        logger.warning("GROUNDING OVERRIDE: confirmed TP cited ungrounded artifacts %s "
                       "-- demoted to monitor.", violations)
    # Surface the violations into state so the response agent can capture them as
    # an active-learning hard example (NC-9); empty list keeps the contract stable
    # for grounded verdicts.
    result["grounding_violations"] = violations
```

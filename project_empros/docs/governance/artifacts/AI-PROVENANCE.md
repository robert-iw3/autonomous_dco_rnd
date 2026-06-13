# AI-PROVENANCE — AI-origin provenance disclosure

*Implementation: `analytics/llm_hunter/agents/controls.py`*

**Execution chain:** Logic → Execution

**1. Logic** — Idempotently prepends an explicit AI-origin disclosure banner to a report.

`analytics/llm_hunter/agents/controls.py:L178-L192`

```python
def stamp_ai_provenance(report: str) -> str:
    """Prepend the AI-origin disclosure banner once (idempotent)."""
    report = report or ""
    if AI_PROVENANCE_BANNER in report:
        return report
    return f"{AI_PROVENANCE_BANNER}\n\n{report}"


# ---------------------------------------------------------------------------
# P2 -- Frontier model version pinning (NIST MP-4.1-007, Risk 2.12 Value Chain)
# Frontier (external SaaS) models must be pinned to an explicit version; a
# floating alias lets a provider silently change verdict behavior with no gate.
# ---------------------------------------------------------------------------

_FRONTIER_API_TYPES = {"anthropic", "openai"}
```

**2. Execution** — Wired into the response agent: every analyst-facing incident report is provenance-stamped before it is returned or persisted.

`analytics/llm_hunter/agents/response.py:L235-L237`

```python
    # AI-origin disclosure (NIST MP-5.1-003): stamp every analyst-facing report as
    # AI-generated so a human consumer is never misled about its source.
    incident_report = stamp_ai_provenance(incident_report)
```

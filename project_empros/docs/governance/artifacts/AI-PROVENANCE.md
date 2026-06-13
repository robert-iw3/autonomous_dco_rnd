# AI-PROVENANCE — AI-origin provenance disclosure

*Implementation: `analytics/llm_hunter/agents/controls.py`*

Machine-generated narrative is stamped with an explicit AI-origin disclosure before it leaves the system.

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

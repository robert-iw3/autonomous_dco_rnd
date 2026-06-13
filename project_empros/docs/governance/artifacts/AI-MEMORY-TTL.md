# AI-MEMORY-TTL — Immunity-memory TTL / expiry

*Implementation: `analytics/llm_hunter/agents/controls.py`*

Immunity-memory entries expire: a recalled memory older than its TTL is non-actionable, preventing stale precedent from driving live decisions.

`analytics/llm_hunter/agents/controls.py:L145-L173`

```python
def memory_is_actionable(payload: dict, now: float, ttl_seconds: int = None) -> bool:
    """Whether a recalled memory point may auto-dismiss a fresh alert. Only an
    eligible, non-expired False Positive qualifies. Legacy points written before
    the TTL existed (no `created_at`) preserve prior behavior and do not expire."""
    p = payload or {}
    if p.get("is_true_positive", True):          # only FPs grant immunity
        return False
    if not p.get("immunity_eligible", True):     # legacy default: eligible
        return False
    ttl = memory_ttl_seconds() if ttl_seconds is None else ttl_seconds
    created = p.get("created_at")
    if created is None:
        return True                              # backward-compat: no expiry info
    try:
        return (float(now) - float(created)) <= ttl
    except (TypeError, ValueError):
        return True


# ---------------------------------------------------------------------------
# P5 -- AI-origin provenance disclosure (NIST MP-5.1-003, Risk 2.7 Human-AI Config)
# Every analyst-facing incident report is stamped as AI-generated so a human
# consumer is never misled about the source of the verdict.
# ---------------------------------------------------------------------------

AI_PROVENANCE_BANNER = (
    "> 🤖 **AI-GENERATED** — produced by the Sentinel Nexus agentic swarm. "
    "Verify forensic claims against source telemetry before acting."
)
```

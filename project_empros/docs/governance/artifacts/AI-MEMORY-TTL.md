# AI-MEMORY-TTL — Immunity-memory TTL / expiry

*Implementation: `analytics/llm_hunter/agents/controls.py`*

**Execution chain:** Logic → Execution → Persistence

**1. Logic** — A recalled immunity memory is actionable only if it is an eligible False Positive still within its TTL (default 30 d).

`analytics/llm_hunter/agents/controls.py:L147-L175`

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

**2. Execution** — Wired into recall: a high-similarity historical FP may short-circuit the swarm only while its memory has not expired.

`analytics/llm_hunter/agents/supervisor.py:L235-L239`

```python
            if hits and memory_is_actionable(hits[0].payload, time.time()):
                m = hits[0]
                logger.warning(
                    f"RAG IMMUNITY TRIGGERED: match with historical False Positive "
                    f"(score={m.score:.3f} ≥ {IMMUNITY_THRESHOLD}). Short-circuiting Swarm."
```

**3. Persistence** — The write path stamps every persisted memory point with created_at, so the recall-side TTL check above can actually expire stale immunity.

`analytics/llm_hunter/agents/response.py:L139-L141`

```python
                    # NIST GV-1.3-005: timestamp so the supervisor's recall can
                    # expire stale immunity rather than entrenching a blind spot.
                    "created_at": time.time(),
```

# NC-3-FRONTIER-PIN — Frontier model boot-time version-pin enforcement

*Implementation: `analytics/llm_hunter/agents/llm_providers.py`*

**Execution chain:** Logic → Boot

**1. Logic** — Classifies a model id as 'floating' (empty, or a moving alias such as *-latest).

`analytics/llm_hunter/agents/controls.py:L195-L201`

```python
def is_floating_model(model: str) -> bool:
    """A model id is 'floating' if empty or it resolves to a moving target
    (e.g. an alias ending in '-latest')."""
    if not model:
        return True
    return "latest" in str(model).strip().lower()

```

**2. Boot** — Wired into chain construction: as the failover chain is built each frontier provider is pin-checked and a floating alias is refused unless explicitly opted in — no silent model drift.

`analytics/llm_hunter/agents/llm_providers.py:L175-L178`

```python
        ok, reason = frontier_pin_allowed(name, cfg)
        if not ok:
            logger.error("Refusing LLM provider: %s", reason)
            continue
```

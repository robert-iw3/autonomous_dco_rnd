# NC-3-FRONTIER-PIN — Frontier model boot-time version-pin enforcement

*Implementation: `analytics/llm_hunter/agents/llm_providers.py`*

A frontier (hosted) model with a floating/unpinned version is rejected at boot unless an explicit override is set — no silent model drift.

`analytics/llm_hunter/agents/llm_providers.py:L148-L161`

```python
def frontier_pin_allowed(name: str, cfg: dict, allow_floating: bool = None):
    """(ok, reason). Internal/sovereign providers and non-frontier api types are
    out of scope (their weights are hash-verified by the supply-chain control)."""
    from agents.controls import is_floating_model
    if allow_floating is None:
        allow_floating = os.getenv("NEXUS_ALLOW_FLOATING_FRONTIER", "").lower() in ("1", "true", "yes")
    cfg = cfg or {}
    if str(name).startswith("internal_") or cfg.get("api_type") not in _FRONTIER_API:
        return True, ""
    if is_floating_model(cfg.get("model", "")) and not allow_floating:
        return False, (f"frontier provider '{name}' has floating model '{cfg.get('model', '')}' "
                       f"-- pin a version or set NEXUS_ALLOW_FLOATING_FRONTIER=1 (NIST MP-4.1-007)")
    return True, ""

```

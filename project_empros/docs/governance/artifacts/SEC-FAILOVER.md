# SEC-FAILOVER — Cascading LLM failover & sovereign degradation

*Implementation: `analytics/llm_hunter/agents/llm_providers.py`*

**Execution chain:** Invocation → Logic → Execution

**1. Invocation** — Every expert (and the supervisor / response / board) is constructed over the failover chain, so degradation is uniform across the swarm.

`analytics/llm_hunter/agents/expert_base.py:L25-L25`

```python
    return [(name, create_react_agent(llm, tools)) for name, llm in build_failover_chain(temperature)]
```

**2. Logic** — Providers are composed into a cascading chain that degrades toward the sovereign on-prem model rather than failing open.

`analytics/llm_hunter/agents/llm_providers.py:L163-L188`

```python
def build_failover_chain(temperature: float = 0.0):
    """
    Ordered list of (provider_name, chat_model) per [hunter].active_provider and
    [hunter].failover_providers. Returns [] if nothing is configured (callers
    already fail conservative on an empty chain).
    """
    llm_cfg = CONFIG.get("llm", {}) or {}
    chain = []
    for name in get_llm_provider_order():
        cfg = llm_cfg.get(name)
        if not cfg:
            continue
        ok, reason = frontier_pin_allowed(name, cfg)
        if not ok:
            logger.error("Refusing LLM provider: %s", reason)
            continue
        try:
            chain.append((name, _build_one(name, cfg, temperature)))
        except Exception as e:
            logger.error(f"Failed to construct LLM provider '{name}': {e}. Skipping.")
    if not chain:
        logger.warning("LLM failover chain is EMPTY -- check [hunter].active_provider in nexus.toml.")
    return chain


@lru_cache(maxsize=1)
```

**3. Execution** — At runtime each node walks the chain provider-by-provider; total failure emits a safe default (monitor) rather than crashing.

`analytics/llm_hunter/agents/response.py:L215-L216`

```python
    for provider_name, llm_instance in LLM_FAILOVER_CHAIN:
        if not circuit_is_callable(provider_name):
```

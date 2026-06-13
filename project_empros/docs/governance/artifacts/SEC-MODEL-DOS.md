# SEC-MODEL-DOS — Model denial-of-service bounding

*Implementation: `analytics/llm_hunter/orchestrator.py`*

**Execution chain:** Invocation → Effect → Effect → Execution → Execution

**1. Invocation** — A hard ceiling on simultaneous investigations…

`analytics/llm_hunter/orchestrator.py:L55-L55`

```python
MAX_CONCURRENT_INVESTIGATIONS = int(os.getenv("NEXUS_MAX_CONCURRENT", "8"))
```

**2. Effect** — …realised as a semaphore…

`analytics/llm_hunter/orchestrator.py:L66-L66`

```python
_investigation_sema = asyncio.Semaphore(MAX_CONCURRENT_INVESTIGATIONS)
```

**3. Effect** — …acquired before any LLM work, bounding model-DoS blast at the investigation entry point.

`analytics/llm_hunter/orchestrator.py:L186-L187`

```python
    async with _investigation_sema:  # bound concurrent investigations (DoS guard)
        await _broadcast_hud(alert, nc_client)
```

**4. Execution** — Per-run the graph carries a LangGraph recursion ceiling that bounds runaway agent loops…

`analytics/llm_hunter/orchestrator.py:L213-L213`

```python
            config_opts = {"configurable": {"thread_id": alert.event_id}, "recursion_limit": RECURSION_LIMIT}
```

**5. Execution** — …and an absolute wall-clock timeout; a timeout escalates to manual review rather than hanging the swarm.

`analytics/llm_hunter/orchestrator.py:L217-L219`

```python
                final_state = await asyncio.wait_for(
                    graph.ainvoke(initial_state, config=config_opts),
                    timeout=INVESTIGATION_TIMEOUT_S,
```

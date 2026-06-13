# SEC-MODEL-DOS — Model denial-of-service bounding

*Implementation: `analytics/llm_hunter/orchestrator.py`*

A hard concurrency ceiling on simultaneous investigations…

`analytics/llm_hunter/orchestrator.py:L55-L55`

```python
MAX_CONCURRENT_INVESTIGATIONS = int(os.getenv("NEXUS_MAX_CONCURRENT", "8"))
```

…enforced by a semaphore acquired before any LLM work — bounding model-denial-of-service blast.

`analytics/llm_hunter/orchestrator.py:L66-L66`

```python
_investigation_sema = asyncio.Semaphore(MAX_CONCURRENT_INVESTIGATIONS)
```

The semaphore gates every investigation entry point.

`analytics/llm_hunter/orchestrator.py:L186-L187`

```python
    async with _investigation_sema:  # bound concurrent investigations (DoS guard)
        await _broadcast_hud(alert, nc_client)
```

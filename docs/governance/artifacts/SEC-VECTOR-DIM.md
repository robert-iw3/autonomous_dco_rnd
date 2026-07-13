# SEC-VECTOR-DIM — Vector dimensionality validation

*Implementation: `analytics/llm_hunter/tools/qdrant_search.py`*

**Execution chain:** Invocation → Execution

**1. Invocation** — The agent-facing vector-search tool entry point.

`analytics/llm_hunter/tools/qdrant_search.py:L50-L50`

```python
    def _run(self, reasoning: str, vector_name: str, target_vector: List[float], limit: int = 5, target_sensor_id: Optional[str] = None) -> str:
```

**2. Execution** — Each search is validated against the expected per-collection dimensionality; a wrong-dimension (malformed/adversarial) probe is rejected before it hits the store.

`analytics/llm_hunter/tools/qdrant_search.py:L58-L72`

```python
        dim_map = {
            "c2_math":        8,
            "sentinel_math":  5,
            "windows_math":   6,   # sysmon + macos
            "deepsensor_math": 4,  # windows_deepsensor EdrRow
            "trellix_math":   6,   # trellix_ens 6D post ENS-3: +entropy_score +frequency_score
            "cloud_flow":     5,
            "network_tap":    8,
        }
        if vector_name not in dim_map:
            return f"Error: Invalid vector_name '{vector_name}'. Must be one of {list(dim_map.keys())}."

        expected_dims = dim_map[vector_name]
        if len(target_vector) != expected_dims:
            return f"Error: '{vector_name}' expects exactly {expected_dims} dimensions, but got {len(target_vector)}."
```

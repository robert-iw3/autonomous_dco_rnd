# SEC-IDEMPOTENT-SOAR — Idempotent SOAR execution & deduplication

*Implementation: `analytics/llm_hunter/agents/response.py`*

Each SOAR dispatch carries a deterministic idempotency key (target + quantised window) so a retried response cannot double-execute.

`analytics/llm_hunter/agents/response.py:L252-L255`

```python
        "reason": reason,
        # Audit / idempotency extras (ignored by the schema, kept for the SOAR log):
        "idempotency_key": f"iso-{target}-{int(float(alert.get('timestamp', 0) or 0) // 900)}",
        "source_type": alert.get("source_type", ""),
```

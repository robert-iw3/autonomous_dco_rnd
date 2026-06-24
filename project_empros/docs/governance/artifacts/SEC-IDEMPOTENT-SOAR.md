# SEC-IDEMPOTENT-SOAR — Idempotent SOAR execution & deduplication

*Implementation: `analytics/llm_hunter/agents/response.py`*

**Execution chain:** Logic → Execution

**1. Logic** — Each SOAR dispatch carries a deterministic idempotency key (target + quantised 15-min window) so a retried response cannot double-execute.

`analytics/llm_hunter/agents/response.py:L374-L377`

```python
        "containment_escalations": protocol["escalations"],
        "containment_coverage": protocol["coverage"],
        "idempotency_key": f"iso-{target}-{int(float(alert.get('timestamp', 0) or 0) // 900)}",
        "source_type": alert.get("source_type", ""),
```

**2. Execution** — The SOAR worker independently TTL-dedups by (incident, action) and suppresses a duplicate containment even across retries — exactly-once at the executor.

`services/worker_soar/src/main.rs:L335-L338`

```rust
                let mut dedup = self.dedup.write().await;
                if dedup.is_duplicate(&dedup_key) {
                    warn!(key = %dedup_key, "Duplicate containment suppressed");
                    continue;
```

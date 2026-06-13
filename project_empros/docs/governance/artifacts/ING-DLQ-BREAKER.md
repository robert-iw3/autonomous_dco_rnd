# ING-DLQ-BREAKER — Durable worker circuit breaker + dead-letter routing

*Implementation: `libs/lib_siem_core/src/lib.rs`*

Workers adapt their batch deadline to observed queue depth; combined with the circuit-breaker pause and dead-letter prefix below, a failing downstream is isolated rather than amplified.

`libs/lib_siem_core/src/lib.rs:L44-L60`

```rust
fn adaptive_deadline(current_ms: u64, messages_fetched: usize, batch_limit: usize) -> u64 {
    if messages_fetched >= batch_limit {
        // Full batch -- more is likely queued; speed up
        (current_ms / 2).max(MIN_BATCH_DEADLINE_MS)
    } else if messages_fetched == 0 {
        // Empty -- low load; back off to reduce NATS fetch pressure
        let grown = (current_ms as f64 * 1.5) as u64;
        grown.min(MAX_BATCH_DEADLINE_SECS * 1000)
    } else {
        // Partial batch -- hold
        current_ms
    }
}

// ── NATS Connection (C2: authenticated connect) ──────────────────────────────
// The production NATS server runs default-deny authorization — every service
// must authenticate with the per-role user provisioned in its env file
```

Default DLQ routing + circuit-breaker pause: poisoned/failed batches are dead-lettered and the worker backs off instead of hot-looping.

`libs/lib_siem_core/src/lib.rs:L104-L110`

```rust
            subject: "nexus.telemetry".into(),
            consumer_name: "Default_Worker_Group".into(),
            dlq_prefix: "nexus.dlq".into(),
            ack_wait_secs: env_u64("WORKER_ACK_WAIT_SECS", 30),
            max_deliver: std::env::var("WORKER_MAX_DELIVER")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(5),
            // Batch deadline: how long to accumulate messages before processing.
```

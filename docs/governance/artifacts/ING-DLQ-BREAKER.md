# ING-DLQ-BREAKER — Durable worker circuit breaker + dead-letter routing

*Implementation: `libs/lib_siem_core/src/lib.rs`*

**Execution chain:** Logic → Effect → Execution

**1. Logic** — Workers adapt their batch deadline to observed queue depth.

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

**2. Effect** — Default DLQ routing + circuit-breaker pause config: poisoned/failed batches are dead-lettered.

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

**3. Execution** — In the consume loop a tripped breaker pauses consumption (metric + backoff) instead of hot-looping a failing downstream.

`libs/lib_siem_core/src/lib.rs:L262-L269`

```rust
        // ── Circuit breaker cooldown ─────────────────────────────────────
        if circuit_open {
            warn!(
                pause_secs = cfg.circuit_breaker_pause_secs,
                "Circuit breaker active. Pausing consumption."
            );
            counter!("nexus_worker_circuit_breaker_trips_total").increment(1);
            tokio::time::sleep(Duration::from_secs(cfg.circuit_breaker_pause_secs)).await;
```

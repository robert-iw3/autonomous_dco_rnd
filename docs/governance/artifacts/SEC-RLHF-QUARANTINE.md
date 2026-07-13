# SEC-RLHF-QUARANTINE — Sybil RLHF poisoning quarantine

*Implementation: `services/worker_rlhf/src/main.rs`*

**Execution chain:** Invocation → Logic → Execution

**1. Invocation** — Operator feedback is ingested batch-by-batch by the RLHF worker.

`services/worker_rlhf/src/main.rs:L90-L91`

```rust
    async fn transmit_batch(
        &self,
```

**2. Logic** — Coordinated override velocity past the global threshold trips an atomic circuit breaker that halts RLHF intake.

`services/worker_rlhf/src/main.rs:L135-L141`

```rust
                let global_count = GLOBAL_OVERRIDE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if global_count > self.global_circuit_breaker_threshold {
                    error!(
                        count = global_count,
                        threshold = self.global_circuit_breaker_threshold,
                        "GLOBAL CIRCUIT BREAKER: override threshold exceeded. Halting RLHF."
                    );
```

**3. Execution** — Operators exhibiting Sybil/poisoning feedback patterns are quarantined so their preference signal cannot corrupt the reward corpus.

`services/worker_rlhf/src/main.rs:L132-L158`

```rust
            };

            if is_override {
                let global_count = GLOBAL_OVERRIDE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                if global_count > self.global_circuit_breaker_threshold {
                    error!(
                        count = global_count,
                        threshold = self.global_circuit_breaker_threshold,
                        "GLOBAL CIRCUIT BREAKER: override threshold exceeded. Halting RLHF."
                    );
                    return Err("Circuit breaker: global override threshold exceeded".into());
                }

                if let Ok(mut velocity) = OVERRIDE_VELOCITY.lock() {
                    let count = velocity.entry(feedback.operator_id.clone()).or_insert(0);
                    *count += 1;
                    if *count > self.per_operator_threshold {
                        warn!(
                            operator = %feedback.operator_id,
                            count = *count,
                            "Poisoning risk: operator exceeded override threshold. Quarantining."
                        );
                        counter!("nexus_rlhf_operator_quarantined_total").increment(1);
                        continue;
                    }
                }
            }
```

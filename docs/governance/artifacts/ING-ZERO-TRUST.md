# ING-ZERO-TRUST — Zero-Trust ingestion gateway (HMAC + 3-tier replay defense)

*Implementation: `services/core_ingress/src/integrity.rs`*

**Execution chain:** Invocation → Logic → Logic → Execution

**1. Invocation** — The ingestion gateway's batch-verification entry point — every inbound batch passes through here before it is accepted.

`services/core_ingress/src/integrity.rs:L211-L213`

```rust
    pub fn verify_batch(
        &self,
        parquet_bytes: &[u8],
```

**2. Logic** — Each batch is authenticated with HMAC-SHA256 over a canonical (parquet ‖ sequence ‖ sensor ‖ timestamp) preimage.

`services/core_ingress/src/integrity.rs:L29-L41`

```rust
fn compute_hmac(
    secret: &[u8],
    parquet_bytes: &[u8],
    sequence: u64,
    sensor_id: &str,
    timestamp: u64,
) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(parquet_bytes);
    mac.update(&sequence.to_be_bytes());
    mac.update(sensor_id.as_bytes());
    mac.update(&timestamp.to_be_bytes());
```

**3. Logic** — HMAC comparison is constant-time, closing the timing-oracle side channel.

`services/core_ingress/src/integrity.rs:L46-L56`

```rust
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

```

**4. Execution** — A bounded replay window + monotonic sequence rejects replayed/out-of-order batches — the third tier of replay defense.

`services/core_ingress/src/integrity.rs:L127-L145`

```rust
    fn record_sequence(&mut self, seq: u64) {
        if self.seen_order.len() >= REPLAY_WINDOW_SIZE {
            if let Some(old) = self.seen_order.pop_front() {
                // O(1) -- VecDeque ring buffer, not Vec::remove(0)
                self.seen_sequences.remove(&old);
            }
        }
        self.seen_sequences.insert(seq);
        self.seen_order.push_back(seq);
        self.last_sequence = seq;
    }
}

// --- Verification Engine -----------------------------------------------------

// --- Ban list persistence helpers --------------------------------------------
// H-R4 fix: banned_sensors was an in-memory HashSet -- cleared on ingress restart,
// allowing previously banned (compromised/replaying) sensors to reconnect immediately.
// Now persisted to a file on every ban update and loaded on startup.
```

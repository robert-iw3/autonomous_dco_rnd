# network_tap (arkime-ml-gateway) test workbench

Tests the network_tap sensor's pipeline: flow capture/feature derivation →
Parquet → HMAC-stamped POST to core_ingress. Single Rust binary crate.

- **tier0** (pure Python) — a logic mirror re-derives the wire contract (48-col
  schema, `X-Sensor-Type`, `sensor_id`, HMAC formula, required headers, default
  gateway URL) and cross-checks it against the real Rust source,
  `[schema_mappings.network_tap]`, and a live mock-ingress round trip.
- **tier1** (container) — `cargo check && cargo test --bin arkime-ml-gateway`:
  the crate compiles and its `#[cfg(test)]` unit tests (feature algorithms) pass.

Run: `./test/run.sh [--all | --tier 0|1]`

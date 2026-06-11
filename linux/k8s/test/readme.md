# falco_transmitter (k8s/Falco) test workbench

Tests the k8s/Falco runtime sensor against the core_ingress contract. Single Rust
binary crate.

- **tier0** (pure Python) — schema + transmission: the Parquet column layout
  mirrored from `falco_schema()` (diffed 1:1 against `main.rs`), `X-Sensor-Type =
  "falco_runtime"`, default gateway URL (`/api/v1/telemetry`, HTTPS, port matches
  core_ingress), HMAC formula + required headers via a mock-ingress round trip,
  and central-pipeline registration of `falco_runtime`.
- **tier1** (container) — `cargo check && cargo test`: the crate compiles and links.

Run: `./test/run.sh [--all | --tier 1]`

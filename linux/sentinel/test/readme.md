# linux-sentinel test workbench

Tests the linux-sentinel sensor (eBPF + YARA + ML kernel-telemetry agent) against
the core_ingress contract. Single Rust binary crate, self-contained (its HMAC
stamper lives in `src/integrity.rs`).

- **tier0** (pure Python):
  - `test_schema_contract.py` / `test_transmission.py` — the Parquet column layout
    mirrored from `parquet_transmitter.rs` vs `[schema_mappings.linux_sentinel]`,
    `X-Sensor-Type = "Linux-Sentinel"`, default gateway URL, and the HMAC formula +
    required headers via a mock-ingress round trip.
  - `test_response.py` — the SOAR response module (DC-N11): verify a Nexus-signed
    task's HMAC, select a fixed `01–06_*.sh` playbook by action (never a task path),
    build `NEXUS_*` env, and an E2E from a platform-signed task to outcome.
- **tier1** (container) — `cargo check && cargo test`: the crate compiles (default
  `integrity` feature) and runs `tests/test_sensor_pipeline.rs` plus the module
  `#[cfg(test)]` golden-vector tests (integrity + response signing parity).

Run: `./test/run.sh [--all | --tier 1]`

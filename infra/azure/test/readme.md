# infra/azure (nsg / activity / entraid connectors) -- Sensor-Side Test Workbench

Validates the three Nexus Azure connectors' own pipeline -- Event-Hub-driven
(blob/event) pull -> `UnifiedFlowRecord` transform -> 31-column Parquet
transmission schema -> HMAC-stamped, JWT-authenticated POST to the Nexus
ingress -- using mock/synthetic data and an in-process mock ingress server.
This workbench does **not** depend on the central
`project_empros/tests/sensors/test_sensor_*.py` suite (that validates Nexus,
not the sensors).

`diff` confirms `transmitter.rs` is byte-identical across all three crates --
one shared workbench covers all three rather than three near-duplicate ones.
(`config.rs`/`cache.rs` differ only in per-connector fields -- nsg additionally
carries `storage_account_url`/`storage_container`/`table_storage_url` and
spool-bound fields that activity/entraid lack or vary -- and string literals.)

## Two tiers

`nexus-azure-{nsg,activity,entraid}-connector` are pure Rust binary crates --
there is no embedded Python interpreter, so pytest cannot drive
`transmit_bytes()`, `to_parquet()`, or `Transformer::transform_*()` directly.
The workbench therefore mirrors the pattern established in
`linux/sentinel/test/`, `infra/network_tap/gateway/test/`, and `infra/aws/test/`:

- **Tier 0** (`tier0/`, pure Python, no containers): a hand-written "logic
  mirror" (`azure_connectors_logic_mirror.py`) independently re-derives the
  pieces of the wire contract that must match byte-for-byte across all three
  connectors -- the 31-column Arrow/Parquet schema (with its lone nullable
  column, identical to `infra/aws`'s -- both emit `UnifiedFlowRecord` onto the
  shared `cloud_flow` named vector), the per-connector `X-Sensor-Type`/default-
  `sensor_id` strings, the two distinct `sensor_id` formulas (see "Other notes"
  below), the HMAC formula, and the 7-header required set -- each annotated
  with the exact source line(s)/function(s) it mirrors. Tier 0 then cross-checks
  that mirror against (a) the real Rust source via regex/string matching against
  `transmitter.rs`, `config.rs`, `main.rs`, and `transformer.rs` for all three
  crates, (b) the central `[schema_mappings.cloud_flow]` contract and
  `cloud_connector.toml` sensor profile, and (c) a live in-process mock ingress
  server (`ThreadingHTTPServer` + capturing handler) that receives synthetic
  HMAC-stamped, bearer-authenticated batches built exactly the way
  `transmit_bytes()` builds its real POST.

- **Tier 1** (`tier1/`, containerized): runs `cargo check` for all three
  crates inside a `rust:1-slim-bookworm` container with a shared
  `CARGO_TARGET_DIR` (they have no path dependencies and a near-identical,
  pure-Rust/`rustls-tls` dependency set -- no rdkafka/cmake/libcurl needed,
  unlike network_tap) to validate that the real Rust source compiles. None of
  the three crates have `#[cfg(test)]` unit tests (confirmed via grep), so
  there is no `cargo test` step -- `cargo check` is the layer that actually
  exercises the real, fixed source Tier 0 can only mirror.

## Running

```bash
./test/run.sh              # Tier 0 only (fast, no Docker/Podman needed)
./test/run.sh --all        # Tier 0 + Tier 1
./test/run.sh --tier 0
./test/run.sh --tier 1     # requires docker or podman
```
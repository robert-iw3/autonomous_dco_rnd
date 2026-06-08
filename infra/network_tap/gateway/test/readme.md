# network_tap (arkime-ml-gateway) -- Sensor-Side Test Workbench

Validates the network_tap sensor's own pipeline -- flow capture/feature
derivation -> Parquet transmission schema -> HMAC-stamped POST to the Nexus
ingress -- using mock/synthetic data and an in-process mock ingress server.
This workbench does **not** depend on the central
`project_empros/tests/sensors/test_sensor_*.py` suite (that validates Nexus,
not the sensor).

## 2 Tests

`arkime-ml-gateway` is a pure Rust binary crate -- there is no embedded Python
interpreter, so pytest cannot drive `transmit_loop()`, `flow_schema()`, or
`LineageStamper::stamp()` directly. The workbench therefore mirrors the
pattern established in `linux/sentinel/test/`:

- **Tier 0** (`tier0/`, pure Python, no containers): a hand-written
  "logic mirror" (`network_tap_logic_mirror.py`) independently re-derives the
  pieces of the wire contract that must match byte-for-byte -- the 48-column
  Arrow/Parquet schema, the `X-Sensor-Type` string, the `sensor_id` derivation,
  the HMAC formula, the required header set, and the default gateway URL --
  each annotated with the exact source line(s) it mirrors. Tier 0 then
  cross-checks that mirror against (a) the real Rust source via regex/string
  matching against `transmit/nexus.rs`, `integrity/stamper.rs`, `config.rs`,
  and `config.toml`, (b) the central `[schema_mappings.network_tap]` contract
  in `project_empros/services/config/nexus.toml`, and (c) a live in-process
  mock ingress server (`ThreadingHTTPServer` + capturing handler) that receives
  synthetic HMAC-stamped batches built exactly the way `transmit_loop()` builds
  its real POST.

- **Tier 1** (`tier1/`, containerized): runs `cargo check && cargo test --bin
  arkime-ml-gateway` inside a `rust:1-slim-bookworm` container (deps mirroring
  the production `gateway/Dockerfile` builder stage) to validate that the real
  Rust source compiles and that its own `#[cfg(test)]` unit tests (e.g.
  `pipeline::features::{test_is_internal_ip, test_port_class}`) pass. This is
  the layer that actually exercises the real algorithm code Tier 0 can only
  mirror. (`--bin`, not `--lib`: `arkime-ml-gateway` is a binary-only crate --
  `src/main.rs`, no `[lib]`/`src/lib.rs` -- so `cargo test --lib` errors with
  "no library targets found"; its unit tests live in the bin target.)

## Running

```bash
./test/run.sh              # Tier 0 only (fast, no Docker/Podman needed)
./test/run.sh --all        # Tier 0 + Tier 1
./test/run.sh --tier 0
./test/run.sh --tier 1     # requires docker or podman
```
# infra/aws (vpc / cloudtrail / guardduty connectors) -- Sensor-Side Test Workbench

Validates the three Nexus AWS connectors' own pipeline -- SQS-driven S3 Parquet
pull -> `UnifiedFlowRecord` transform -> 31-column Parquet transmission schema
-> HMAC-stamped, JWT-authenticated POST to the Nexus ingress -- using
mock/synthetic data and an in-process mock ingress server. This workbench does
**not** depend on the central `project_empros/tests/sensors/test_sensor_*.py`
suite (that validates Nexus, not the sensors).

`diff` confirms `transmitter.rs` and (modulo two per-connector string literals)
`config.rs` are byte-identical across all three crates -- one shared workbench
covers all three rather than three near-duplicate ones.

## 3 tiers

`nexus-aws-{vpc,cloudtrail,guardduty}-connector` are pure Rust binary crates --
there is no embedded Python interpreter, so pytest cannot drive `transmit_bytes()`,
`to_parquet()`, or `Transformer::transform_*()` directly. The workbench therefore
mirrors the pattern established in `linux/sentinel/test/` and `infra/network_tap/gateway/test/`:

- **Tier 0** (`tier0/`, pure Python, no containers): a hand-written "logic
  mirror" (`aws_connectors_logic_mirror.py`) independently re-derives the
  pieces of the wire contract that must match byte-for-byte across all three
  connectors -- the 31-column Arrow/Parquet schema (with its lone nullable
  column), the per-connector `X-Sensor-Type`/default-`sensor_id` strings, the
  `sensor_id` pipe-delimited-triple formula, the HMAC formula, and the
  7-header required set -- each annotated with the exact source line(s) it
  mirrors. Tier 0 then cross-checks that mirror against (a) the real Rust
  source via regex/string matching against `transmitter.rs`, `config.rs`, and
  `transformer.rs` for all three crates, (b) the central
  `[schema_mappings.cloud_flow]` contract and `cloud_connector.toml` sensor
  profile, and (c) a live in-process mock ingress server (`ThreadingHTTPServer`
  + capturing handler) that receives synthetic HMAC-stamped, bearer-authenticated
  batches built exactly the way `transmit_bytes()` builds its real POST.

- **Tier 1** (`tier1/`, containerized): runs `cargo check` for all three
  crates inside a `rust:1-slim-bookworm` container with a shared
  `CARGO_TARGET_DIR` (they have no path dependencies and a near-identical,
  pure-Rust/`rustls-tls` dependency set -- no rdkafka/cmake/libcurl needed,
  unlike network_tap) to validate that the real Rust source compiles. None of
  the three crates have `#[cfg(test)]` unit tests (confirmed via grep), so
  there is no `cargo test` step -- `cargo check` is the layer that actually
  exercises the real, fixed source Tier 0 can only mirror.

- **Tier2** is the IaC layer — and rather than a generic `terraform validate` pass,
  its centerpiece (`test_iac_runtime_contract.py`) applies logic-mirror philosophy
  to the **IaC↔application seam**: it cross-checks that the deploy IAM policy grants
  *exactly* the AWS actions the connector consumes at runtime, that the S3 notification
  `filter_suffix` matches the connector's Parquet `CONTENT_TYPE` (imported straight from
  the tier0 mirror, so the two halves can't drift), that the DynamoDB `hash_key` matches
  how the connector keys metadata, and that the StackSet FlowLog actually emits `vpc-id`
  Parquet to S3. A missing `sqs:DeleteMessage` or an `s3:GetObject` on the wrong ARN
  passes tier0+tier1 and 403s in prod — this is the gap that closes it.

## Running

```bash
./test/run.sh              # Tier 0 only (fast, no Docker/Podman needed)
./test/run.sh --all        # Tier 0 + Tier 1
./test/run.sh --tier 0
./test/run.sh --tier 1     # requires docker or podman
./test/run.sh --tier 2     # IaC validation
```
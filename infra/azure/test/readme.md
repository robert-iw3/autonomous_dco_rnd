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

## Three tiers

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

- **Tier 2** (`tier2/`, containerized): validates the `deploy/terraform/` IaC
  for all three connectors. Unlike the AWS workbench (which uses moto for an
  emulated `terraform apply`), there is no Azure equivalent of moto, so
  convergence is split:
  - `terraform init` + `terraform validate` + `terraform fmt -check` run in
    CI (provider schema validation, no live credentials needed).
  - `terraform apply` is deferred to the gated real-Azure run.
  - **Posture** (`test_iac_posture.py`): asserts Azure-specific security
    controls via static TF parse -- Storage TLS 1.2 / GRS replication /
    private containers / blob versioning / delete-retention; EventHub Standard
    SKU / message retention; listen-only authorization rules (no send, no
    manage); checkov scan with a small documented N/A skip list.
  - **Runtime contract** (`test_iac_runtime_contract.py`): asserts the IaC
    wires the event-source correctly per connector -- EventGrid BlobCreated →
    EventHub for nsg; `azurerm_monitor_diagnostic_setting` with required log
    categories (Administrative / Security / Policy) for activity;
    `azurerm_monitor_aad_diagnostic_setting` with all five Entra ID log
    categories for entraid. Also asserts the connector egress to Nexus is
    still Parquet (guards tier0 contract drift).

## Running

```bash
./test/run.sh              # Tier 0 only (fast, no Docker/Podman needed)
./test/run.sh --all        # Tier 0 + Tier 1 + Tier 2
./test/run.sh --tier 0
./test/run.sh --tier 1     # requires docker or podman
./test/run.sh --tier 2     # requires docker or podman
```
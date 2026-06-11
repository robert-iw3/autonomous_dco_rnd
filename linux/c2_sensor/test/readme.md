# c2_sensor test workbench

Tests the C2 sensor (Python ML engine + Rust workspace) against the core_ingress
contract.

- **tier0** (pure Python) — ML algorithms (`BeaconML.detect_dga`,
  `detect_beaconing_list`) against the real `python_engine`; transmission
  conformance (HMAC formula, headers, content-type, gateway URL) via a mock
  ingress; and a data-contract check that drives the real
  `NexusForwarder.extract_to_spool()` and validates the Parquet schema against
  `[schema_mappings.linux_c2]`.
- **tier1** (container) — `cargo check`: the Rust workspace compiles
  (`active_defender`, `api_server`, `core_hunter`, `shared_models`, `telemetry_ingest`).

Run: `./test/run.sh [--all | --tier 1]`

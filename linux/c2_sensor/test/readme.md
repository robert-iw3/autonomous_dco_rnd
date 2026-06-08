# c2_sensor Test Workbench

Validates the sensor end to end against the central `core_ingress` contract.

## Tiers

- **Tier 0** (`tier0/`, pytest, no containers) -- algorithmic validation of the
  ML engine (`BeaconML.detect_dga`, `detect_beaconing_list`) against the real
  `python_engine` modules; transmission-layer conformance (HMAC formula,
  required headers, `Content-Type`, gateway URL) verified with an in-process
  mock ingress server; and an end-to-end data-contract check that seeds a
  synthetic SQLite `flows` table, drives the real `NexusForwarder.extract_to_spool()`
  pipeline, and validates the resulting Parquet schema against
  `[schema_mappings.linux_c2]` in the central `nexus.toml`.

- **Tier 1** (`tier1/`, cargo check in a container via docker/podman) --
  build/compile validation of the Rust workspace (`active_defender`,
  `api_server`, `core_hunter`, `shared_models`, `telemetry_ingest`).

## Running

```bash
./test/run.sh            # Tier 0 only (fast, no Docker/Podman needed)
./test/run.sh --all      # Tier 0 + Tier 1
./test/run.sh --tier 1   # Rust build validation only
```
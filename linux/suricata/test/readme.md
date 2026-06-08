# suricata Test Workbench

Validates the suricata_eve sensor end to end against the central `core_ingress`
contract. Unlike `c2_sensor` (a Python ML engine + Rust agent), the suricata
transmitter is a **single Rust binary crate** with no Python component, so the
algorithm itself is tested in-language via `cargo test` while the cross-language
wire contract (HMAC, headers, schema column names) is independently re-derived
and checked from Python.

## 2 Tiers

- **Tier 0** (`tier0/`, pytest, no containers) -- schema-contract validation:
  cross-checks the Parquet column layout mirrored from `eve_schema()`
  (`eve_logic_mirror.EVE_SCHEMA_COLUMNS`, annotated with its `main.rs` source
  lines) against `[schema_mappings.suricata_eve]` in the central `nexus.toml`,
  confirms `sensor_type = "suricata_eve"` is not registered in core_ingress's
  `build_exclusion_rules()` CrossOsCollision map, and validates the default
  gateway URL routes to `/api/v1/telemetry`. It also independently re-derives
  the HMAC integrity formula and required-header set and fires synthetic
  batches at an in-process mock ingress server, validating the full wire
  contract end to end (HMAC cross-check, header presence, `Content-Type`,
  tamper detection) the same way `main.rs`'s `transmit()` does.

- **Tier 1** (`tier1/`, cargo check + cargo test in a container via docker/podman) --
  build/compile validation of `suricata_transmitter`, plus its embedded
  `#[cfg(test)]` suite which exercises the *real* `eve_schema()`,
  `events_to_parquet()` (round-tripping synthetic EVE alert/flow events through
  a real Arrow→Parquet→Arrow cycle and asserting on decoded column values),
  `mitre_field()` (MITRE ATT&CK tactic/technique metadata extraction), and
  `Stamper::stamp()` (HMAC formula, sequence monotonicity, tamper detection).

## Running

```bash
./test/run.sh            # Tier 0 only (fast, no Docker/Podman needed)
./test/run.sh --all      # Tier 0 + Tier 1
./test/run.sh --tier 1   # Rust build + test validation only
```
# linux-sentinel Test Workbench

Validates the linux-sentinel sensor (eBPF + YARA + ML kernel-telemetry agent)
end to end against the central `core_ingress` contract. Like `suricata`, the
sensor is a **single Rust binary crate** with no Python component, so the
algorithm itself is tested in-language via `cargo test` (the existing
`tests/test_sensor_pipeline.rs` integration suite) while the cross-language
wire contract (HMAC, headers, schema column names) is independently re-derived
and checked from Python.

## 2 Tiers

- **Tier 0** (`tier0/`, pytest, no containers) -- schema-contract validation:
  cross-checks the Parquet column layout mirrored from the Nexus-transmission
  Arrow schema in `parquet_transmitter.rs`
  (`sentinel_logic_mirror.EXPECTED_SENTINEL_PARQUET_COLUMNS`, annotated with its
  source lines) against `[schema_mappings.linux_sentinel]` in the central
  `nexus.toml`, confirms the wire `X-Sensor-Type = "Linux-Sentinel"` matches
  both the transmitter source and `sensor_profiles/linux_sentinel.toml`
  (intentionally distinct from the lowercase `schema_mappings` table key used
  for `worker_qdrant`/`worker_rules` duck-typing), and validates the default
  gateway URL. It also independently re-derives the HMAC integrity formula
  (shared via `nexus_integrity::LineageStamper` across every Nexus sensor) and
  required-header set, and fires synthetic batches at an in-process mock
  ingress server -- validating the full wire contract end to end (HMAC
  cross-check, header presence, `Content-Type`, tamper detection) the same way
  `parquet_transmitter.rs`'s forwarder task does.

- **Tier 1** (`tier1/`, cargo check + cargo test in a container via docker/podman) --
  build/compile validation of `linux-sentinel` (with its default `integrity`
  feature, which links `nexus_integrity` via a Cargo path dependency into
  `windows/windows_xdr_dev`), plus the real `tests/test_sensor_pipeline.rs`
  integration suite (Parquet schema/column assertions, sensor-type/header
  contract cross-checks against source via `include_str!`, MITRE
  tactic/technique model coverage).

  Because of the `nexus_integrity` path dependency
  (`linux/sentinel/Cargo.toml`: `nexus_integrity = { path =
  "../../windows/windows_xdr_dev/nexus_integrity" }`, pulled in by the
  `default = ["integrity"]` feature), the Docker build context for this tier is
  the **repo root**, not the crate directory -- see `tier1/Dockerfile` for the
  explicit `COPY` list that preserves both `linux/sentinel` and the
  `windows/windows_xdr_dev` workspace (manifest + its three member crates) at
  their real relative paths.

## Running

```bash
./test/run.sh            # Tier 0 only (fast, no Docker/Podman needed)
./test/run.sh --all      # Tier 0 + Tier 1
./test/run.sh --tier 1   # Rust build + test validation only
```
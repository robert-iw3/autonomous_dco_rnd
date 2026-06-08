# falco_transmitter (k8s/Falco) Test Workbench

Validates the k8s/Falco runtime sensor end to end against the central
`core_ingress` contract. Like `suricata`, the sensor is a **single Rust
binary crate** (`falco_transmitter`) with no Python component and no
workspace path-dependencies, so the algorithm is build/link-validated
in-language via `cargo check`/`cargo test` while the cross-language wire
contract (HMAC, headers, schema column names, gateway routing) is
independently re-derived and checked from Python.

## 2 Tiers

- **Tier 0** (`tier0/`, pytest, no containers) -- schema-contract +
  transmission-layer validation:
  - Cross-checks the Parquet column layout mirrored from `falco_schema()` in
    `main.rs` (`falco_logic_mirror.FALCO_SCHEMA_COLUMNS`, regex-extracted and
    diffed 1:1 against the real source) for internal well-formedness
    (no duplicates, routing/identifier columns present, raw-fields catch-all
    present).
  - Confirms the wire `X-Sensor-Type = "falco_runtime"` literal matches the
    transmitter source (both the Parquet column value and the request header).
  - Confirms the default gateway URL points at `/api/v1/telemetry`, matches
    `Config::from_env()` and `launch.sh`, requires HTTPS, and that its port
    agrees with the canonical `core_ingress [ingress] bind_addr` (even though
    its hostname style -- `nexus-edge:8080` -- differs from the
    HAProxy-fronted `nexus-edge.local:443` convention used by
    sentinel/network_tap/c2_sensor; see Findings).
  - Independently re-derives the HMAC integrity formula (shared via the
    `Stamper`/`compute_hmac` pattern across every Nexus sensor) and the
    required-header set, then fires synthetic batches at an in-process mock
    ingress server -- validating the full wire contract end to end (HMAC
    cross-check, header presence, `Content-Type`, tamper detection) the same
    way `transmit_parquet()`'s forwarder does.
  - Confirms (`TestCentralRegistration`) that `falco_runtime` is fully wired
    into the central pipeline -- a real registration gap found and closed
    while building this workbench, see Findings below.

- **Tier 1** (`tier1/`, cargo check + cargo test in a container via
  docker/podman) -- build/compile validation. `falco_transmitter` is a plain
  standalone Tokio/Arrow/Parquet/reqwest binary crate with no eBPF/YARA native
  compilation and no embedded `#[cfg(test)]` suite, so this tier is pure
  build/link validation: `cargo check` for type/borrow correctness against the
  real `Cargo.toml` dependency set, then `cargo test` (which builds the crate
  in test profile and reports 0 embedded tests -- confirming the binary links
  cleanly).

## Running

```bash
./test/run.sh            # Tier 0 only (fast, no Docker/Podman needed)
./test/run.sh --all      # Tier 0 + Tier 1
./test/run.sh --tier 1   # Rust build validation only
```
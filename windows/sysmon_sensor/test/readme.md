# sysmon_sensor Test Workbench

Validates the sensor's own collect → normalise → transform-to-Parquet →
sign-and-transmit pipeline end to end, using synthetic Sysmon events and an
in-process mock ingress server. (The central `project_empros/tests/sensors/
test_sensor_sysmon.py` suite validates the *Nexus* side -- schema mappings,
worker_qdrant registration, nexus.toml alignment -- this workbench validates
the sensor side.)

- **Tier 0** (`tier0/`, pytest, no containers) -- the whole workbench.
  `sysmon_sensor` is a pure-Python endpoint agent with no Rust crate, so there
  is no Tier 1 cargo-check stage.

  - `test_algorithms.py` -- drives the real `schema.py` feature-computation
    functions (`compute_command_entropy`, `compute_parent_child_score`,
    `compute_integrity_score`, `compute_grant_access_score`,
    `compute_driver_trust_score`, `compute_features`) with synthetic field
    values, including the documented LOLBin parent→child pairs and the
    6D `windows_math` vector ordering.

  - `test_data_contracts.py` -- drives the real `SysmonSensor._normalise()`
    with synthetic raw Sysmon `EventData` dicts across multiple Event IDs
    (1 process-create, 3 network-connection, 6 driver-load, 10 process-access,
    22 DNS query), feeds the normalised records into the real
    `ParquetShipper._to_parquet()`, and validates the resulting Parquet bytes
    -- column set, computed feature vector, `payload_raw` forensic copy --
    against `[schema_mappings.sysmon_sensor]` in the central
    `project_empros/services/config/nexus.toml`.

  - `test_transmission.py` -- transmission-layer conformance: the real
    `ParquetShipper._compute_hmac()` cross-checked against an independent
    re-derivation of the `core_ingress::compute_hmac` formula
    (`HMAC-SHA256(payload || BE64(seq) || sensor_id_utf8 || BE64(ts))`);
    the literal header/`Content-Type`/`SENSOR_TYPE` contract in `_ship()`;
    middleware URL path alignment across the shipper default, the
    `sysmon_sensor.toml` sensor profile, and `middleware.toml`'s
    `gateway_url`; and an end-to-end run of the real `_ship()` against an
    in-process `ThreadingHTTPServer` mock ingress that captures the POST,
    confirms all required headers/HMAC are self-consistent, and proves a
    tampered payload no longer matches its stamped HMAC.

## Running

```bash
./test/run.sh
```
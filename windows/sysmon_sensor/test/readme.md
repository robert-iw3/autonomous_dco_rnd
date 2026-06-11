# sysmon_sensor test workbench

Tests the Sysmon sensor's collect → normalise → Parquet → sign-and-transmit
pipeline (plus its SOAR response). Pure-Python agent, so everything is **tier0**
(no cargo stage).

- `test_algorithms.py` — the real `schema.py` feature math
  (entropy, parent/child, integrity, grant-access, driver-trust, `compute_features`),
  incl. LOLBin pairs and the 6D `windows_math` vector order.
- `test_data_contracts.py` — drives `SysmonSensor._normalise()` across Event IDs
  (1/3/6/10/22) → `ParquetShipper._to_parquet()` and validates the Parquet schema
  against `[schema_mappings.sysmon_sensor]`.
- `test_transmission.py` — `_compute_hmac()` vs the independent core_ingress HMAC
  formula, the header/content-type/`SENSOR_TYPE` contract, gateway URL alignment,
  and an E2E `_ship()` against a mock ingress (incl. tamper detection).
- `test_response_channel.py` — the SOAR response channel (DC-N11): verify a
  Nexus-signed task, fixed `0X_*.ps1` by action (never a task path), `NEXUS_*` env,
  gateway-URL derivation, and an E2E from a platform-signed task to outcome.

Run: `./test/run.sh`

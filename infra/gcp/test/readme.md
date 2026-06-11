# infra/gcp — Audit / SCC / VPC connector test workbench

Tests the three GCP connectors' shared pipeline: Pub/Sub pull → 31-column Parquet
→ HMAC-stamped, JWT-authed POST to core_ingress (ack only on 200; no local spool).

- **tier0** (pure Python) — wire contract: 31-col schema (names/order/nullability),
  per-connector `sensor_type`/`sensor_id`/`event_type` (incl. VPC's
  `project|env|region|subnetwork`), `bearer_auth` + 7 headers + Parquet
  content-type, HMAC formula, `spool_replay = false`, SCC dedup + severity→score,
  and a mock-ingress round trip.
- **tier1** (container) — `cargo check`: all three crates compile.
- **tier2** (container) — Terraform convergence (init/validate/fmt), posture
  (Pub/Sub ack deadline, 24h retention, retry/backoff, VPC DLQ, checkov) and
  runtime contract (subscription↔topic↔sink IAM wiring, SCC notification filter).

Run: `./test/run.sh [--all | --tier 0|1|2]`

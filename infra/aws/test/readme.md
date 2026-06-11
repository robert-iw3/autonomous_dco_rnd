# infra/aws — VPC / CloudTrail / GuardDuty connector test workbench

Tests the three AWS connectors' shared pipeline: SQS→S3 Parquet pull →
`UnifiedFlowRecord` transform → 31-column Parquet → HMAC-stamped, JWT-authed POST
to core_ingress. `transmitter.rs` is byte-identical across all three, so one
workbench covers them all.

- **tier0** (pure Python) — a logic mirror re-derives the wire contract (31-col
  schema, per-connector `X-Sensor-Type`/`sensor_id`, HMAC formula, 7 required
  headers) and cross-checks it against the real Rust source, the central
  `[schema_mappings.cloud_flow]` + `cloud_connector.toml`, and a live mock-ingress round trip.
- **tier1** (container) — `cargo check`: all three crates compile.
- **tier2** (container) — IaC↔runtime contract: the deploy IAM grants exactly the
  AWS actions the connector uses, S3 notification suffix matches the Parquet
  content-type, DynamoDB key matches, plus posture/convergence.

Run: `./test/run.sh [--all | --tier 0|1|2]`

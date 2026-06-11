# infra/azure — NSG / Activity / EntraID connector test workbench

Tests the three Azure connectors' shared pipeline: Event-Hub pull →
`UnifiedFlowRecord` transform → 31-column Parquet → HMAC-stamped, JWT-authed POST
to core_ingress. `transmitter.rs` is byte-identical across all three, so one
workbench covers them all.

- **tier0** (pure Python) — a logic mirror re-derives the wire contract (31-col
  `cloud_flow` schema, per-connector `X-Sensor-Type`/`sensor_id` formulas, HMAC
  formula, 7 required headers) and cross-checks it against the real Rust source,
  the central `[schema_mappings.cloud_flow]` + `cloud_connector.toml`, and a live
  mock-ingress round trip.
- **tier1** (container) — `cargo check`: all three crates compile.
- **tier2** (container) — Terraform posture (Storage TLS1.2/GRS/private/versioning,
  EventHub listen-only auth, checkov) and runtime contract (per-connector event
  source: EventGrid→EventHub for nsg, diagnostic settings for activity/entraid;
  egress still Parquet).

Run: `./test/run.sh [--all | --tier 0|1|2]`

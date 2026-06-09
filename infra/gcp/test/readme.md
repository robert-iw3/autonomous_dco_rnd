# GCP Connector Test Suite

Three-tier validation for the GCP connectors (`audit`, `scc`, `vpc`).

## Tiers

### Tier 0 — Pure Python (no containers)

Runs anywhere with `pytest` installed.

```bash
pytest infra/gcp/test/tier0 -v
```

Validates:

- Rust transmitter files are byte-identical across `audit`/`scc`/`vpc` where required
- `auth_token` field and `bearer_auth` present in every transmitter (401-prevention)
- `spool_replay = false` (Pub/Sub pull is queue-backed; replay would produce duplicates)
- 31-column Parquet schema: correct column names, order, and nullability
- `sensor_type`, `sensor_id`, `event_type` hardcoded values per connector
- VPC 4-component `sensor_id` formula: `project_id|environment|region|subnetwork`
- `gcp_connector.toml` documents all three sensor types
- Content-Type header is `application/vnd.apache.parquet`
- 7 required HTTP headers (6 operational + `Authorization` bearer)
- SCC dedup (`FindingCache`) and severity→score mapping
- HMAC formula: `HMAC-SHA256(secret, payload || BE64(seq) || sensor_id_utf8 || BE64(ts))`
- Mock-ingress end-to-end: connector sends, ingress validates, returns 200

### Tier 1 — Cargo check (containerized)

Builds a Rust slim-bookworm image and runs `cargo check` against all three crates.

```bash
bash infra/gcp/test/tier1/run.sh
```

Validates that all three crates compile cleanly with the current Rust toolchain.
Catches type errors, missing fields, and broken imports before a full `cargo build`.

### Tier 2 — IaC validation (containerized)

Builds an image with Terraform 1.9 and checkov, then runs pytest against
`test/tier2/`.

```bash
bash infra/gcp/test/tier2/run.sh
# or from the top-level orchestrator:
bash infra/gcp/test/run.sh --tier 2
```

#### Convergence tests (`test_iac_convergence.py`)

| Test | What it checks |
|------|----------------|
| `test_init_and_validate` | `terraform init -backend=false` + `terraform validate` succeeds for each connector |
| `test_fmt_clean` | `terraform fmt -check -recursive` finds no reformatting needed |

#### Posture tests (`test_iac_posture.py`)

| Test | What it checks |
|------|----------------|
| `test_ack_deadline_seconds` | Subscription `ack_deadline_seconds = 60` (6× batch timeout buffer) |
| `test_message_retention_duration` | `message_retention_duration = "86400s"` (24h — survives full gateway outage) |
| `test_retry_policy_exists` | `retry_policy` block present — prevents tight failure loop on nack |
| `test_retry_policy_backoff_values` | `minimum_backoff=10s`, `maximum_backoff=600s` |
| `test_dlq_topic_exists_for_vpc` | vpc: DLQ topic exists alongside main topic |
| `test_dead_letter_policy_max_delivery_attempts` | vpc: `max_delivery_attempts = 10` |
| `test_checkov_enforces_all_but_documented_na` | All checkov checks pass; only `CKV_GCP_83` (CMEK) is skipped with documented rationale |

#### Runtime-contract tests (`test_iac_runtime_contract.py`)

| Test | What it checks |
|------|----------------|
| `test_subscription_topic_references_stack_topic` | Subscription `topic` attribute references the stack's own topic resource |
| `test_topic_resource_is_declared` | Topic resource the subscription references is actually declared in the stack |
| `test_iam_member_grants_publisher_role` | IAM member role is `roles/pubsub.publisher` (audit/vpc) |
| `test_iam_member_references_sink_writer_identity` | IAM `member` references the sink's `writer_identity` (not hardcoded) |
| `test_iam_unique_writer_identity_enabled` | Logging sink `unique_writer_identity = true` (per-sink service account) |
| `test_notification_config_exists` | `google_scc_notification_config` declared (scc only) |
| `test_pubsub_topic_references_stack_topic` | SCC notification `pubsub_topic` references stack topic (scc only) |
| `test_streaming_config_filter_is_active_only` | SCC `streaming_config.filter` contains `ACTIVE` (scc only) |
| `test_sink_filter_scopes_to_correct_log_type` | Logging sink `filter` contains the correct log type substring (audit/vpc) |
| `test_required_outputs_declared` | All required outputs (`subscription_id`, `topic_id`, `sink_writer`) declared |
| `test_subscription_id_references_correct_subscription` | `subscription_id` output references the right subscription `.name` |
| `test_topic_id_references_correct_topic` | `topic_id` output references the right topic `.id` |
| `test_sink_writer_references_correct_sink` | `sink_writer` output references the right sink `.writer_identity` (audit/vpc) |
| `test_wire_content_type` | Logic mirror `CONTENT_TYPE == "application/vnd.apache.parquet"` |
| `test_spool_replay_is_false` | Logic mirror `SPOOL_REPLAY is False` (Pub/Sub pull is queue-backed) |

## GCP Connector Architecture

Each connector uses **Pub/Sub pull subscription**:

1. Google Cloud routes events to a Pub/Sub topic:
   - **audit**: Cloud Logging → `google_logging_project_sink` → topic
   - **scc**: Security Command Center → `google_scc_notification_config` → topic
   - **vpc**: VPC Flow Logs → `google_logging_project_sink` → topic
2. The Rust connector pulls messages from the subscription in batches
3. Each batch is serialized as a 31-column Parquet file and POSTed to the Nexus gateway
4. The connector **acks only after** the gateway returns 200; **nacks on failure** so Pub/Sub redelivers
5. `spool_replay = false` — the queue is the source of truth; no local spool file

### Sensor IDs

| Connector | Formula | Example |
|-----------|---------|---------|
| `audit` | `gcp-audit-connector-default` (static) | `gcp-audit-connector-default` |
| `scc` | `gcp-scc-connector-default` (static) | `gcp-scc-connector-default` |
| `vpc` | `{project_id}\|{environment}\|{region}\|{subnetwork}` | `my-project\|prod\|us-central1\|default` |

### Wire contract

All three connectors POST to the Nexus gateway with the following 7 HTTP headers:

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <auth_token>` |
| `Content-Type` | `application/vnd.apache.parquet` |
| `X-Batch-Sequence` | Monotonic batch counter (u64 BE) |
| `X-Batch-Timestamp` | Unix timestamp (u64 BE) |
| `X-Sensor-Id` | Sensor ID string |
| `X-Sensor-Type` | `gcp_audit` / `gcp_scc` / `gcp_vpc_flow` |
| `X-Batch-HMAC` | `HMAC-SHA256(secret, payload‖BE64(seq)‖sensor_id‖BE64(ts))` |
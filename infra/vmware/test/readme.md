# VMware Connector Test Suite

Three-tier test suite validating the VMware syslog connector: wire contract, compilation, and IaC posture.

## Running

```bash
# Tier0 — pure Python, runs anywhere pytest is installed
cd infra/vmware/test
python3 -m pytest tier0/ -v

# All tiers (requires Docker)
bash infra/vmware/test/run.sh --all

# Individual tiers
bash infra/vmware/test/run.sh --tier 0
bash infra/vmware/test/run.sh --tier 1
bash infra/vmware/test/run.sh --tier 2

# Tier2 directly (container)
bash infra/vmware/test/tier2/run.sh
```

## What each tier covers

### Tier0 — wire contract (pure Python)

| Test class | What it verifies |
|---|---|
| `TestParquetSchema` | 31 columns, correct order, only `ml_result` nullable |
| `TestWireHeaders` | All 7 required HTTP headers, bearer auth, Parquet content-type |
| `TestSensorIdSubsystems` | `\|nsx`, `\|vcenter`, `\|esxi` suffixes in the right code paths |
| `TestNSXVerdictMapping` | DROP/REJECT/DENY/BLOCK → score 25 / Network_Deny; PASS/ALLOW/ACCEPT → 0 / Network_Flow |
| `TestVCenterMITREMappings` | All MITRE techniques and tactics present in transformer.rs |
| `TestCEFPriority` | CEF check precedes NSX flow check in transform_line |
| `TestBeaconingCache` | `src_ip\|dst_ip` key format, cache.observe() called |
| `TestSpoolReplay` | `spool_replay: true` hardcoded (syslog requires local replay on restart) |
| `TestAuthTokenConfig` | `AUTH_TOKEN` env var required; `auth_token` field in Config |
| `TestHMACFormula` | HMAC-SHA256(secret, payload ‖ BE64(seq) ‖ sensor_id ‖ BE64(ts)) |
| `TestMockIngressEndToEnd` | Full POST cycle to a local mock gateway; header/body verification |

### Tier1 — compilation

`cargo check` on the full connector crate in a Rust slim-bookworm container.

### Tier2 — IaC

| Test class | What it verifies |
|---|---|
| `TestTerraformInit` | `terraform init -backend=false` succeeds |
| `TestTerraformValidate` | `terraform validate` reports no errors |
| `TestTerraformFmt` | `terraform fmt -check -recursive` no formatting drift |
| `TestBackendDeclared` | Explicit `backend "local" {}` block present |
| `TestProviderVersionPinned` | `vmware/nsxt ~> 3.4`, `hashicorp/vsphere ~> 2.6` |
| `TestTerraformVersionPinned` | `required_version >= 1.9` |
| `TestSSLEnforcement` | `allow_unverified_ssl = false` in both providers |
| `TestSensitiveVariables` | nsxt_username, nsxt_password, vsphere_user, vsphere_password all `sensitive = true` |
| `TestRequiredVariables` | All 11 required input variables declared |
| `TestLogLevels` | DEBUG/INFO/WARNING/ERROR in log_levels (DFW packet telemetry) |
| `TestNSXTExporterWiring` | Exporter server/port/protocol reference variables; includes DEBUG |
| `TestOutputsContract` | `collector_endpoint`, `nsxt_exporter` outputs declared correctly |
| `TestConnectorEgressIsParquet` | transmitter.rs sets Parquet content-type and uses ArrowWriter |
| `TestProviderAuthentication` | nsxt/vsphere providers reference credential variables |
| `TestRuntimeEnvDocumentation` | AUTH_TOKEN, GATEWAY_URL, INTEGRITY_SECRET, SENSOR_ID, SYSLOG_BIND documented in main.tf |
| `TestCheckov` | No HIGH/CRITICAL checkov findings |

## Design notes

- **spool_replay = true** is hardcoded because VMware syslog is not queue-backed. If the connector crashes, unsent batches on disk are replayed on restart. This is the opposite of the GCP connectors (where the Pub/Sub queue retains unacked messages).
- **HMAC uses the base `sensor_id`** (not the `|nsx` / `|vcenter` / `|esxi` suffixed form). The subsystem suffix appears only in the Parquet `sensor_id` column, not in the HTTP header or HMAC calculation.
- **CEF detection takes priority** over NSX firewall detection in `transform_line`. This is because vCenter can forward CEF-formatted events over the same syslog channel as NSX-T.
- **Local backend** is intentional for on-premises deployments. For multi-operator or CI/CD workflows, switch to a compatible remote backend (Terraform Cloud, S3-compatible, etc.).
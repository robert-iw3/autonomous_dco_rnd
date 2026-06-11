# infra/vmware — syslog connector test workbench

Tests the VMware syslog connector: wire contract, compilation, and IaC posture.

- **tier0** (pure Python) — wire contract: 31-col schema (only `ml_result`
  nullable), 7 headers + bearer + Parquet content-type, `|nsx|vcenter|esxi`
  sensor-id subsystems, NSX verdict→score mapping, vCenter MITRE mappings, CEF-
  before-NSX precedence, beaconing cache key, `spool_replay = true` (syslog isn't
  queue-backed), HMAC formula, and a mock-ingress round trip.
- **tier1** (container) — `cargo check`: the connector crate compiles.
- **tier2** (container) — Terraform init/validate/fmt, provider/version pinning,
  SSL enforcement, sensitive vars, required vars/outputs, NSX-T exporter wiring,
  runtime-env docs, and checkov (no HIGH/CRITICAL).

Run: `bash run.sh [--all | --tier 0|1|2]`

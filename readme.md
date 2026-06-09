# R&D for AI-Driven Security Operations

Primary research and development repository for **Project EMPROS** — an autonomous defensive architecture that collapses the time between detection, triage, and containment. EMPROS fuses kernel-level endpoint telemetry, network forensics, and cloud-native log correlation into a unified pipeline where domain-specific LLMs transform fragmented security events into governed, autonomous response.

> [!NOTE]
> This repository is used solely to track project progress and backup restore points. Some sections are excluded via `.gitignore` for production. Certain directories will not compile or function exactly as shown.
>
> Sensors are thoroughly tested with full transmission to `project_empros`. MLOps recursive self-improvement is in active beta.

---

## Architecture

### Endpoint Telemetry (`linux/` | `windows/`)
> Personally developed sensor codebases are restricted and will not compile.

Low-level system hooks capture process execution, file I/O, network connections, DNS, and TLS fingerprints. Linux sensors use eBPF CO-RE probes; Windows uses ETW + native Rust FFI. On-sensor ML (KMeans, DBSCAN, Isolation Forest, DGA, UEBA) produces MITRE ATT&CK-attributed scores before telemetry leaves the host. Armed profiles trigger autonomous process termination and XDP-level network blackholing.

### Network Telemetry (`network_tap/`)
Raw traffic from hardware taps is forked into OpenSearch (forensic indexing) and a Rust refinery extracting deep L7 context (identity, timing, DNS, HTTP, TLS, geo) for ML consumption. Records are serialized to compressed Parquet with zero data-loss SQLite WAL buffering.

### Cloud Integration (`infra/aws/` | `infra/azure/` | `infra/gcp/`)
Event-driven Rust microservices normalize AWS (VPC Flow, CloudTrail, GuardDuty), Azure (NSG Flows, Activity Logs, Entra ID), and GCP (Audit Logs, VPC Flow, SCC) logs through a unified schema with cryptographic integrity envelopes. Connectors scale via KEDA/Event Hub consumers.

### Analysis Engine (`project_empros/`)
> Middleware fan-out, Rust ingress/routing, and the dataplane are public. MLOps, orchestration, and automated deployment are proprietary and redacted.

The intelligence hub processes scored telemetry through:

- **Contextual Correlation** — maps events against network topology, environmental baselines, and cross-host behavioral patterns
- **Behavioral Analysis** — a sovereign LLM swarm (Models A–D) evaluates TTPs via sensor-space feature vectors projected directly into embedding space
- **Autonomous SOAR** — governed pipeline handles alert evaluation, blast-radius assessment, and containment, with deterministic circuit breakers enforcing human review for high-impact actions

---

## Stack

| Layer | Technology |
|---|---|
| Sensors & ingest | Rust (eBPF, ETW, network tap, cloud ETL, Nexus gateway) |
| On-sensor ML | Python (BeaconML, UEBA), C/eBPF (kernel probes, XDP) |
| LLM orchestration | Python + LangGraph (agentic swarm, MLOps pipeline) |
| Windows instrumentation | PowerShell / C# (ETW, enterprise deployment) |
| Infrastructure | Terraform (AWS, Azure, GCP, VMware) |

---

*Research and development sandbox. All materials are proof-of-concept implementations. Each subdirectory contains its own documentation with deployment instructions and architecture detail.*

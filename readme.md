# R&D for AI-Driven Security Operations

This repo is the primary research and development repository for **Project EMPROS**, an autonomous defensive architecture engineered to collapse the time between detection, triage, and incident eradication. EMPROS fuses kernel-level endpoint telemetry, network forensics, and cloud-native log correlation into a unified analysis pipeline, where domain-specific LLMs transform fragmented security events into actionable intelligence and governed response.

> [!NOTE]
>
> This repository is used solely to track project progress and backup restore points.
>
> Please note that some sections are ignored via .gitignore for production. Consequently, certain directories will not function exactly as shown.
>
> All sensors have been thoroughly tested and working with full transmission to project_empros, currently MLOps (recursive self learning) is in beta stage and showing "spooky" progress.

## Technical Architecture

EMPROS adopts a modular, high-performance architecture designed to handle enterprise-scale telemetry across endpoint, network, and cloud boundaries without inducing system instability.

### 1. Endpoint Telemetry Layer (`linux/` | `windows/`) [proprietary -- except for suricata, falco, trellix, and sysmon integrations]

> [!NOTE]
>
> Only personally developed sensor codebases remain private, core functionality is restricted and they will not compile.

* **High-Performance Instrumentation:** Low-level system hooks capture process execution, file system modifications, network connections, DNS resolution, and TLS fingerprints. Linux sensors use eBPF CO-RE probes attached to kernel tracepoints; Windows sensors use ETW sessions with native Rust FFI for behavioral analysis at wire speed.
* **Efficient Data Handling:** Zero-copy ring buffer consumption, Welford online aggregation for packet statistics, and WAL-mode SQLite batching minimize kernel-space footprint and eliminate lock contention under sustained event loads.
* **On-Sensor ML:** Behavioral clustering (KMeans, DBSCAN, Isolation Forest), UEBA temporal profiling, DGA classification, and volumetric exfiltration detection run locally against per-process baselines, producing MITRE ATT&CK-attributed scores before telemetry leaves the host.
* **Active Defense:** In armed deployment profiles, scored detections trigger autonomous containment via process termination and XDP/firewall-level network blackholing, governed by configurable thresholds and dry-run safety modes.

### 2. Network Telemetry Layer (`network_tap/`) [automation -- redacted]

* **Dual-Path Pipeline:** Raw traffic captured from enterprise core switches via hardware taps is forked into two independent streams -- one indexing session metadata into OpenSearch for human forensic investigation, the other passing through a Rust refinery that extracts deep Layer 7 context (identity, timing, volume, DNS, HTTP, TLS certificates, geolocation) for downstream ML consumption.
* **Durable Transmission:** Extracted records are spooled to a local SQLite WAL and serialized into compressed Parquet payloads for transmission to the central analysis engine, ensuring zero data loss during upstream outages.

### 3. Cloud Integration Layer (`infra/aws` | `infra/azure`)

* **Multi-Cloud ETL:** Event-driven Rust microservices extract, transform, and normalize cloud-native logs (AWS VPC Flow Logs, CloudTrail, GuardDuty; Azure NSG Flows, Activity Logs, Entra ID), enabling cross-domain/infrastructure correlation.
* **Scalable Ingestion:** Connectors scale elastically via KEDA (AWS/EKS) and Event Hub consumers (Azure/AKS), transmitting Parquet payloads with cryptographic integrity envelopes through the central Nexus gateway.
* **Planned Expansion:** [Validation & Testing] GCP (VPC Flow Logs, Cloud Audit Logs, Security Command Center) and VMware (NSX-T Distributed Firewall, vCenter Events, ESXi Host Logs) connectors are on the integration roadmap.

### 4. Analysis Engine (`project_empros/`) [mlops (proprietary)|automated deploy|orchestration -- redacted]

> [!NOTE]
>
> What is public -- middleware fan out | rust ingress & routing | the dataplane itself can be used for your own data wrangling desires.

The central engine functions as the intelligence hub, processing scored telemetry from all upstream sources through three distinct layers:

* **Contextual Correlation:** Distinguishes between legitimate administrative behavior and adversarial anomalies by mapping events against known network topology, environmental baselines, and cross-host behavioral patterns across the deployment fleet.
* **Behavioral Analysis:** A sovereign LLM swarm trained on adversarial tradecraft evaluates TTPs (Tactics, Techniques, and Procedures) rather than static indicators. Sensor-space feature vectors are projected directly into the model's embedding space, enabling mathematical reasoning over anomaly geometry rather than text-serialized metrics.
* **Automated Triage & Response:** A governed SOAR pipeline automates alert evaluation, multi-host blast-radius assessment, and containment orchestration, with deterministic circuit breakers enforcing human-in-the-loop review for high-impact actions. A sovereign MLOps pipeline validates every model checkpoint against a regression gate before production deployment.

## Core Capabilities

* **Adversarial Tradecraft Modeling:** LLMs are fine-tuned to interpret complex, multi-stage event sequences -- including lateral movement, credential abuse, and living-off-the-land techniques -- that traditional detection engines frequently miss.
* **Cross-Domain Correlation:** Endpoint behavior, network forensics, and cloud control-plane activity converge through a unified schema with cryptographic provenance, allowing the analysis engine to detect distributed attack patterns that span infrastructure boundaries.
* **Governed Autonomous Response:** Orchestrates the entire response workflow from initial detection through anomaly verification to threat eradication, with blast-radius validation, asset criticality weighting, and cascading provider failover ensuring operational safety at scale.

## Development Stack

* **Rust:** Sensor ingest pipelines, heuristic scoring, active defense, API servers, cloud ETL connectors, network telemetry refinery, and the Nexus ingress gateway.
* **Python:** On-sensor ML (BeaconML, UEBA profiling), LLM swarm orchestration (LangGraph), sovereign MLOps pipeline, and telemetry forwarding.
* **C / eBPF:** Kernel-space probes for Linux network, process, and DNS telemetry; XDP packet filtering for active defense.
* **PowerShell / C#:** Windows endpoint instrumentation, ETW integration, and enterprise deployment automation.
* **Terraform:** Cloud infrastructure provisioning and automated log source enablement across AWS, Azure, GCP, and VMware.

---

*This repository is a research and development sandbox. All materials are provided as proof-of-concept implementations for future downstream integration. Each subdirectory contains its own documentation with deployment instructions and component-specific architecture detail.*
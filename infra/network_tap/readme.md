### Summary
---

This is a dual-path network telemetry pipeline. Raw traffic from enterprise core switches is captured through hardware taps, deduplicated, and fed into an Arkime sensor that forks the data into two independent streams. The first stream indexes session metadata into a self-cleaning OpenSearch cluster so human analysts retain full forensic search and investigation capability. The second stream passes through a high-throughput Rust gateway that filters protocol noise, extracts 42 contextual fields -- covering identity, timing, volume, DNS, HTTP, TLS certificates, and geolocation -- and durably spools them into a SQLite WAL. From there, records are serialized into Zstd-compressed Parquet payloads and transmitted over HTTPS to an upstream Axum gateway where the LLM training stack resides. The result is that a downstream language model receives dense, rich, investigation-ready network flow records it can use to learn the behavioral rhythm of the network and provide contextual analysis when an agentic AI investigates anomalous traffic.

<p align="center">
  <img src="img/network_defense_stack_data_flow.svg" alt="Flow" width="100%" />
</p>

### The Core Intent
---

Standard network logs strip away the behavioral nuances and Layer 7 context that Large Language Models (LLMs) need to accurately reason about network traffic. This project exists to bridge that gap.

The Network Defense Stack is a specialized, dual-path telemetry pipeline designed to translate raw network traffic into dense, context-rich datasets optimized specifically for downstream AI/LLM training. It achieves this high-fidelity data extraction without disrupting the localized, forensic search capabilities that human analysts rely on for daily incident response.

### Architecture & Data Flow
---

Raw traffic from enterprise core switches is captured out-of-band via hardware taps, deduplicated at the packet broker, and ingested by an Arkime sensor. The telemetry is then seamlessly forked into two independent streams:

* **The Human Path (Local Forensics):** Session metadata is continuously indexed into a self-cleaning OpenSearch cluster. This preserves 100% of existing operational functionality, allowing human analysts to run queries and investigate traffic via the standard UI.
* **The Machine Path (LLM Pipeline):** Raw session profiles are ingested by a high-throughput Rust gateway. This refinery filters out broadcast noise and extracts 42 distinct contextual fields, covering identity footprints, temporal variance, volumetric ratios, DNS requests, HTTP metadata, and TLS certificate details.

### Durability & Transmission
---

To guarantee zero data loss during high-velocity spikes or upstream outages, the Rust gateway utilizes a Sentinel pattern. Records are durably spooled into a local SQLite Write-Ahead Log (WAL) before being serialized into dense, Zstd-compressed Parquet payloads. These matrices are then transmitted over HTTPS to an upstream Axum gateway where the LLM training stack resides.

### The Output
---

By preserving exact spatial variances, timing rhythms, and deep L7 metadata, the downstream language model receives the unpolluted behavioral DNA of the network. This provides the AI with the exact structural resolution required to learn standard network rhythms and contextually investigate anomalous traffic patterns.
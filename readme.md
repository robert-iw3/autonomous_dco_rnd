### What is the point of this project?

The future of cybersecurity is defined by autonomous, machine-speed engagements where AI-driven offensive agents (Red AI) clash with AI-driven **defensive systems (Blue AI)**. Because human-operated tools can no longer keep pace with the scale of modern cyberattacks, artificial intelligence is now the primary driving force on both sides of the digital battleground.

AI is both the master key and the unpickable lock; the winner is simply whoever turns it faster.

### Sensor to LLM Data Flow

> [!NOTE]
> This logical data flow diagram is updated to represent the current architecture.

<p align="center">
  <img src="img/logical_flow_v3.svg" alt="Flow" width="100%" />
</p>

---

### Directory Structure:
```bash
PROJECT_EMPROS/
├── analytics/                  # Layer 3 agentic AI swarm
│   └── llm_hunter/             # LangGraph DAG: supervisor + host/net/cloud/nettap experts + review board + response; tools, controls, RAG memory
├── services/                   # Layer 1 & 2 high-speed Rust services
│                               #   core_ingress (Zero-Trust gateway) + workers: qdrant (math tripwires), rules (Sigma), s3_archive, soar, rlhf; shared nexus.toml
├── middleware/                 # Layer 1.5 Rust ETL fanout (own Cargo workspace, config, deploy, certs)
├── libs/                       # Shared Rust libraries (lib_siem_core: schema-neutral structs, NATS/integrity helpers)
├── det_chamber/                # Live acquisition + detonation: engine (Win/Linux sandbox), intake service, agents, config, deploy (isolated IaC)
├── mlops/                      # Sovereign multi-model training & inference pipeline
│                               #   data/ (pcaps, suricata_rules, staging, training, evals) · models/ (base, adapters, baseline) ·
│                               #   scripts/ (stage_* corpora, 0N_* train/eval/serve) · corpus_templates/ (per-TTP) · deployment/ (vLLM quadlets)
├── detection_training/         # SIEM detection content exports: sigma + datadog, elastic-security, google-secops, kql, sentinel_one, splunk, suricata
├── orchestration/              # Top-level deploy driver: templates, pipelines (GitLab CI), scripts (01–07 stages), environments (dev/prod)
├── infrastructure/             # IaC + config mgmt: ansible (roles, group_vars vault, inventory), terraform (aws/vmware), certs, haproxy, nats, prometheus, qdrant
├── hardening/                  # Reusable OS-hardening Ansible role (defaults, handlers, tasks, templates)
├── operations/                 # Layer 4 event-driven C&C: ephemeral infra (Traefik+Authentik), n8n SOAR, playbooks (linux/windows), webui, scripts
├── deployment_prep/            # Air-gap bundle builder: image manifests, scan, scripts, requirements (Docker + Podman)
├── tests/                      # 550+ tests: offline contract suites, docker lab harnesses (lab_*), simulation red-team playbooks, Rust integration
├── docs/                       # Reference docs & living trackers: infrastructure_specifications, security_controls,
│                               #   nist_ai_600_1_control_tracker, mlops_pipeline, mlops_maturation_plan
├── planning_docs/              # Consolidated BACKLOG.md (open items) + plan docs (Det Chamber, performance, test labs, ADDON) + archive/
├── change_logs/                # Detailed codebase changelogs (changelog_DDMONYY.md)
├── img/                        # Architecture/flow diagrams (SVG + planning_diagrams)
└── data/                       # Runtime data scratch (gitignored)
```

---

### Core Architecture: The Autonomous Triad

Sentinel Nexus operates on a multi-tier correlation engine designed to shift the kill chain left, eliminating the noise of 50,000+ endpoints and delivering deterministic attack graphs at machine speed.

**1. Layer One: Vector Tripwires (The Unknown Unknowns)**
High-speed mathematical filtering via Qdrant. Edge agents stream multi-dimensional UEBA telemetry (5D Sentinel, 8D C2) directly into memory-mapped HNSW indices. This layer triggers on purely behavioral anomalies (e.g., high-entropy execution followed by low-jitter beaconing) using Cosine similarity, catching zero-days and LotL attacks that bypass standard signatures.

**2. Layer Two: Deterministic Engine (The Known Unknowns)**
A zero-copy Rust worker (`worker_rules`) subscribed natively to the NATS JetStream Parquet bus. It performs high-speed, in-memory string evaluation against known IoCs and Sigma-style rules (e.g., specific DGAs, `uid=33` executing `wget`). Matches are pushed instantly to a distributed Redis queue.

**3. Layer Three: The Agentic Closer (LLM RAG Pivot)**
The `llm_hunter` daemon continuously monitors both the Qdrant anomalies and the Redis deterministic queue. Upon receiving a trigger, the LLM executes a time-bounded pivot against the historical Parquet data, extracting the correlated network flow and host execution to generate a zero-hallucination, definitive attack narrative.

**4. Sovereign Threat Intelligence (Air-Gapped OpenCTI)**
A permanent, air-gapped OpenCTI 6.8 STIX platform running on the `ti` tier (10.0.90.x). No external connectors. Pre-loaded with the MITRE ATT&CK enterprise bundle on first deploy. Agents query it via `ti_lookup.py` → `OpenCTIProvider` (GraphQL) to enrich observables with kill-chain phases, malware families, threat actor attribution, and TLP markings -- without leaving the sovereign environment. External TI providers (VirusTotal, AbuseIPDB, OTX, X-Force, GreyNoise) are also supported when API keys are available but are never required.

---

## End Game

### Sentinel Nexus: End-State Sovereign Multi-Model Architecture

### 1. Architectural Overview & Strategic Intent

The ultimate operational state of the Sentinel Nexus ecosystem utilizes a **Federated Swarm Topology**. Relying on a single Large Language Model (LLM) to perform network baseline anomaly detection, endpoint payload analysis, and automated containment evaluation introduces latency, context-window saturation, and logic degradation.

By organizing distinct, specialized neural networks (both generative and unsupervised) into a Directed Acyclic Graph (DAG), the architecture scales deterministically. This document details the technical specifications and integration points of the four primary models operating within the air-gapped environment.

---

### 2. System Integration Topology (The Multi-Model DAG)

<p align="center">
  <img src="img/simple_diag.svg" alt="Flow" width="100%" />
</p>

---

### 3. Detailed Model Specifications

#### Model A: The Network Baseline Engine (Math Tripwire)

* **Purpose:** Establish the mathematical definition of "normal" organic network traffic and trigger downstream generative analysis strictly upon deviation. Generative LLMs cannot inspect every network packet; this model acts as the high-throughput, low-latency pre-filter running ahead of the entire swarm.
* **Architecture:** Bidirectional LSTM Autoencoder -- encoder `BiLSTM(8→64) → Linear(128→32)`, decoder `BiLSTM(32→64) → Linear(128→8)`. Small enough (~1 MB weights) to run inference on CPU at wire speed with no GPU dependency.
* **Data Input:** 8-dimensional normalized flow feature vectors extracted from network_tap SPI events: `byte_ratio`, `avg_inter_arrival`, `variance_inter_arrival`, `ratio_small_packets`, `ratio_large_packets`, `payload_entropy`, `session_duration_ms`, `packets_src`. Per-feature min/max normalization parameters are computed at training time and saved alongside the weights.
* **Execution Logic:** Consumes events from NATS JetStream (`nexus.network_tap.telemetry`). Maintains per-IP-pair sliding window buffers (LRU-evicted, up to 500k tracked pairs for 50k+ endpoint deployments). Runs reconstruction inference every `stride` flows. Reconstruction error is compared against the calibrated μ+3σ threshold.
* **Trigger Condition:** When MSE exceeds the threshold, an anomaly alert is published to `nexus.alerts.baseline` containing the src/dst IP pair, reconstruction error, and normalized anomaly score. The `nettap_expert` swarm agent picks up this signal for L7 forensic analysis.
* **Deployment:** Runs on the **analytics node** (CPU-only) via `baseline-detector.service` Podman Quadlet. Co-located with the LLM Hunter swarm -- no GPU required.

#### Model B: The Adversarial Pattern Classifier

* **Purpose:** Classify adversarial network intent across two complementary domains -- C2 beacon/exfiltration flow statistics and full 42-field Layer 7 session forensics -- producing deterministic MITRE ATT&CK attribution with containment recommendations.
* **Architecture:** Configurable via `mlops/model_config.toml` (`[models.b]`). Default: **Mistral Small 3.1 24B**, QLoRA fine-tuned in 4-bit NF4 quantization. The genuine 128k long-context window (GQA-backed, improved over Nemo's SWA) allows the model to hold large arrays of sequential network sessions in a single forward pass without truncation.
* **Training Corpus (Dual-Track Curriculum):**
  * **Track 2 (C2 Beacons):** Linux/Windows C2 flow statistics (jitter CV, outbound ratio, DGA entropy, beacon interval) with MITRE TTP labels derived from live S3 archives. Eval gate: ≥98% TTP mapping accuracy.
  * **Track 4 (Nettap SPI):** Full 42-field L7 session windows with derived analyst responses: JA3 fingerprint analysis, TLS certificate anomalies, DNS tunneling indicators, ephemeral port usage, lateral movement classification. Eval gate: ≥95% forensic quality.
* **Integration Points:**
  * `net_expert` agent -- C2 flow analysis: jitter/beacon/exfil/DGA detection against `linux_c2`/`windows_c2` telemetry and Suricata IDS correlation.
  * `nettap_expert` agent -- Full-PCAP L7 session forensics including Model A baseline cross-reference path.
* **Deployment:** `vllm-network.service` on **Compute Node Beta GPUs 0-1** (160 GB NVLink). `tensor_parallel_size=2`, `max_model_len=131072`, `enforce_eager=false` for maximum PagedAttention KV cache throughput. Port 8001.

#### Model C: The Spatial Endpoint Expert

* **Purpose:** Execute deep forensic evaluation on host operating systems (Windows/Linux) when triggered by `worker_qdrant` math anomalies or Sigma/YARA rule matches, with the unique ability to "sense" raw sensor-space geometry directly in its latent state before processing text.
* **Architecture:** Configurable via `mlops/model_config.toml` (`[models.c]`). Default: **Llama-3.1 8B Instruct**, QLoRA fine-tuned with a **Multi-Head SpatialProjector** -- named MLP projection heads per sensor vector space mapping sensor math into the model's embedding space (dimension set by `model_c_hidden_dim`, default 4096 for Llama-3.1-8B):
  * `c2_math` (8D) → `hidden_dim` -- Windows/Linux C2 flow behavioral vector
  * `sentinel_math` (5D) → `hidden_dim` -- Linux Sentinel process anomaly vector
  * `windows_math` **(6D)** → `hidden_dim` -- Sysmon sensor: command_entropy, parent_child_score, integrity_score, anomaly_score, **grant_access_score** (EventID 10), **driver_trust_score** (EventID 6/7)
  * `deepsensor_math` **(4D)** → `hidden_dim` -- Windows DeepXDR EdrRow UEBA: score, avg_entropy, max_velocity, event_count
  * `trellix_math` **(4D)** → `hidden_dim` -- Trellix ENS proxy: severity_score, threat_score, action_score, anomaly_score
  * `cloud_flow` (5D) → `hidden_dim` -- Cloud VPC/audit behavioral vector
  * `network_tap` (8D) → `hidden_dim` -- Network tap statistical feature vector
  * `embedding_384` (384D) → `hidden_dim` -- Dense semantic embedding (MiniLM, golden dataset proxy)
* **Training Corpus:** Track 1 -- Qdrant vector+context pairs per named vector space with explicit `vector_name` routing; per-head gradient tracking ensures each projection head receives training signal. Also trained on all 13 TTP behavioral corpora (**3,730 SFT records, 266 active classes** -- 12 TTP phase corpora + cross-source temporal) for host forensic pattern recognition.
* **Integration Point:** `host_expert` agent -- receives process execution metadata with UEBA math vectors spliced at the `<|spatial_vector|>` token position. Outputs host-isolation recommendations, process termination lists, and lateral movement indicators.
* **Deployment:** `vllm-inference.service` on **Compute Node Beta GPUs 2-3** (160 GB NVLink, shared with Model D). Port 8000.

#### Model D: The SOAR Critic (Blast Radius Evaluator)

* **Purpose:** Serve as the final autonomous decision gate before any containment action is dispatched. Weighs confirmed threat evidence against operational blast radius -- preventing catastrophic self-inflicted outages from over-eager containment of critical infrastructure.
* **Architecture:** Configurable via `mlops/model_config.toml` (`[models.d]`). Default: **Gemma-3-4B**, fine-tuned with **Direct Preference Optimization (DPO/IPO)**. At 4B parameters (~8GB VRAM) it frees significant headroom on the GPU pair shared with Model C. IPO is selected over standard DPO for its stability in constrained, low-cardinality decision spaces. The model outputs exactly one of three decision tokens: `CONFIRM_QUARANTINE`, `MANUAL_REVIEW`, or `DISMISS_FALSE_POSITIVE`.
* **Training Corpus:** DPO preference pairs -- threat-based, governance-based, and baseline-triggered categories. Category 4 hard negatives (TP look-alikes that should be dismissed) are generated from the TTP behavioral corpus FP records.
* **Execution Logic:** The `response.py` agent computes the `DisruptionIndex = Σ(AssetValue x ContainmentImpact)` for the proposed target set. The critic **fails CLOSED** -- if the server is unreachable, the verdict is automatically demoted to `manual_review_required`.
* **HitL Circuit Breaker:** `CONFIRM_QUARANTINE` is overridden to `manual_review_required` if: DisruptionIndex > 0.5, any target has AssetValue ≥ 0.9, or the target set covers > 20% of the known fleet.
* **Deployment:** `vllm-critic.service` on **Compute Node Beta GPUs 2-3** (shared with Model C, `gpu_memory_utilization=0.45`). Temperature 0, `max_tokens=16`. Port 8002.

---

### 3a. Candidate Model Reference

Model selection is fully configurable via `mlops/model_config.toml` and `NEXUS_MODEL_*` environment variables. The tables below document every model evaluated for each role against the specific demands of an **Agentic AI Swarm SOC** operating at 50,000+ endpoint scale with sovereign air-gap requirements.

**How to switch:** Update `[models.b]`, `[models.c]`, or `[models.d]` in `mlops/model_config.toml` and re-run `make train-all`. No other file needs changing. For Model C, also update `hidden_dim` if switching to a different architecture family.

---

#### Model B Candidates -- Network Adversarial Pattern Classifier

**Hard requirements:** Genuine 128k+ context for L7 session arrays · vLLM compatible · QLoRA fine-tunable · Fits 2xA100 80GB

| Model | Params | Context | Key strength for this role | Key weakness | Status |
|-------|--------|---------|---------------------------|--------------|--------|
| **Mistral Small 3.1 24B** | 24B | 128k | GQA-backed long-context (improved over Nemo SWA), strong structured JSON, 24B reasoning depth | Larger than Nemo -- more VRAM per inference slot | **Active default** |
| Mistral-Nemo 12B (Jul 2024) | 12B | 128k SWA | Lighter, fast inference | SWA degrades effective recall past ~32k -- Track 4 windows often exceed this | Previous default |
| Gemma 3 27B (Mar 2025) | 27B | 128k | Google post-training quality, excellent structured output | 3B larger than Small 3.1, slightly tighter VRAM budget at 128k | Alternative |
| Qwen2.5-14B (Sep 2024) | 14B | 128k | Best-in-class RULER long-context score at weight class, excellent JSON fidelity | Smaller than Nemo at same task complexity | Alternative |
| Llama 4 Scout (Apr 2025) | 17B active / 109B MoE | 10M | Effectively unlimited context for session arrays | MoE QLoRA training is complex -- expert routing gradients are uneven | Future v2 |

---

#### Model C Candidates -- Spatial Endpoint Expert

**Hard requirements:** HF Transformers `inputs_embeds` path (no vLLM) · `hidden_dim` must match `model_c_hidden_dim` in config · QLoRA fine-tunable

| Model | Params | Context | `hidden_dim` | Projector change? | Key strength | Status |
|-------|--------|---------|--------------|-------------------|--------------|--------|
| **Llama-3.1-8B** | 8B | 128k | 4096 | None | Direct upgrade from Llama-3-8B: 8k→128k context, same architecture, zero projector work | **Active default** |
| Llama-3-8B (Apr 2024) | 8B | 8k | 4096 | None | Well-tested base | 8k context truncates long process trees | Previous default |
| DeepSeek-R1-Distill-Llama-8B | 8B | 128k | 4096 | None | Reasoning distillation -- richer chain-of-thought in forensic analysis | Thinking tokens add output length | Alternative |
| Gemma-3-9B (Mar 2025) | 9B | 128k | 3840 | Yes -- set `hidden_dim=3840` + retrain projector | Strong instruction quality, newer training data | Alternative |
| Qwen2.5-7B (Sep 2024) | 7B | 128k | 3584 | Yes -- set `hidden_dim=3584` + retrain projector | Smaller, strong structured output | Alternative |
| Llama-3.3-70B | 70B | 128k | 8192 | Yes -- set `hidden_dim=8192` + retrain projector | Substantially better forensic reasoning | Future |

---

#### Model D Candidates -- SOAR Critic (Blast Radius Evaluator)

**Hard requirements:** DPO/IPO alignable · Shares GPU 2-3 with Model C -- smaller = more headroom · Deterministic 3-class output

| Model | Params | Context | VRAM @bf16 | Key strength | Key weakness | Status |
|-------|--------|---------|-----------|--------------|--------------|--------|
| **Gemma-3-4B** | 4B | 128k | ~8 GB | Smallest viable option -- frees ~8 GB vs 8B models on shared GPU; Google instruction quality is strong at 4B | Edge-case blast-radius reasoning at 4B is weaker than larger models | **Active default** |
| Phi-4-mini 3.8B (Feb 2025) | 3.8B | 128k | ~7.5 GB | Exceptional reasoning-per-parameter ratio; smallest VRAM footprint | Less proven for DPO alignment in SOC context | Alternative |
| Gemma-3-9B (Mar 2025) | 9B | 128k | ~18 GB | Better edge-case reasoning; same family as default | Nearly 2.5x VRAM of Gemma-3-4B | Upgrade path |
| Qwen2.5-7B (Sep 2024) | 7B | 128k | ~14 GB | Excellent structured decision-making, strong DPO results | 6 GB more than Gemma-3-4B on shared GPU | Alternative |
| Llama-3.1-8B | 8B | 128k | ~16 GB | Same family as Model C -- shared base download | Largest of the practical options for shared GPU | Alternative |
| Llama-3.3-70B | 70B | 128k | ~140 GB | Highest reasoning quality for difficult blast-radius edge cases | Requires dedicated GPU node | Future |

---

### 4. Hardware and Computational Topology

The quad-model architecture runs across two physically separate compute tiers. Strict GPU-to-model allocation prevents VRAM contention and ensures each model's latency budget is met under concurrent investigation load.

#### The Inference Cluster Specifications

* **Analytics Node (CPU -- Model A + LLM Swarm):**
  * **Workload:** Model A BiLSTM-AE baseline detector (CPU inference) + the full LLM Hunter swarm orchestrator (LangGraph DAG, DuckDB pivots, Qdrant vector search, OpenCTI TI enrichment). Also the MLOps training node -- runs data spooling, all training tracks, evaluation gates, and OCI artifact push.
  * **Hardware:** CPU-optimized node. Recommended: `r6i.2xlarge` (AWS) or equivalent -- 64 GB RAM, 8 vCPU, NVMe scratch for DuckDB S3 queries. **No GPU required.**
  * **Memory Profile:** Dominated by DuckDB in-memory Parquet scans and Qdrant client connections. The BiLSTM-AE weights are under 1 MB.

* **Compute Node Beta (Generative Swarm -- 4x A100 80GB NVLink):**
  * **Workload:** Models B, C, and D -- the three fine-tuned LLM inference servers.
  * **Hardware:** 4x NVIDIA A100 80GB, interconnected via NVLink for high-bandwidth tensor sharding. 320 GB total VRAM.
  * **GPU Allocation (hard partition):**

| GPUs | Service | Role | Framework | `tensor_parallel` | VRAM Budget |
|------|---------|------|-----------|-------------------|-------------|
| 0, 1 | `vllm-network.service` | Model B -- Network Adversarial | vLLM AsyncEngine | 2 | scales with `MODEL_B_BASE` weights + 128k KV |
| 2, 3 | `vllm-inference.service` | Model C -- Spatial Endpoint Expert | HF Transformers (`device_map=auto`) | n/a | capped at `HF_MAX_MEMORY_PER_GPU` (default 36 GiB) |
| 2, 3 | `vllm-critic.service` | Model D -- SOAR Critic | vLLM AsyncEngine | 2 | `GPU_MEMORY_UTILIZATION=0.45` -- shared with C |

* **Threat Intelligence Node (TI -- OpenCTI Stack):**
  * **Host:** `10.0.90.10` (`ti` Ansible group)
  * **Workload:** Air-gapped OpenCTI 6.8 + Elasticsearch 8.19 + RabbitMQ 4.1 + MinIO. Runs permanently alongside core infra -- not ephemeral.
  * **Access:** Analytics agents query `http://10.0.90.10:8080/graphql` (HAProxy-proxied) using the read-only `OPENCTI_AGENT_TOKEN`. No external network access required after initial MITRE ATT&CK bundle import.

#### 5. Security & Isolation Controls

* **Prompt Injection Defense:** All adversary-controlled strings (command lines, DNS queries, file paths) retrieved from S3/Qdrant are HTML-escaped and wrapped in `<untrusted_payload>` tags by the DuckDB and Qdrant tools before reaching any LLM prompt. Every system prompt explicitly forbids obeying instructions found inside those tags. A per-investigation canary token is injected into agent prompts as a leak tripwire -- detection halts the SOAR pipeline.
* **Containerized Air-Gap:** All inference ports bind strictly to the `deepnet` overlay network. `TRANSFORMERS_OFFLINE=1` and `HF_DATASETS_OFFLINE=1` are set in every inference container -- no model can initiate outbound network calls at runtime.
* **Sovereign Threat Intelligence:** OpenCTI runs fully air-gapped (no external connectors). The analytics agents' TI enrichment path (`ti_lookup.py` → OpenCTIProvider → OpenCTI GraphQL) never leaves the sovereign network. External TI providers (VirusTotal etc.) are opt-in via API key environment variables only.
* **Model Checkpoint Integrity (ATLAS AML.T0044):** All `.safetensors` weight files are SHA-384 hashed at training time and verified before any weights are loaded into VRAM. Pickle-based weight files (`.pt`, `.pth`, `.bin`) are explicitly banned -- any detection halts the service with a `SECURITY BREACH` log entry. The integrity manifest is regenerated on every `make deploy` run.

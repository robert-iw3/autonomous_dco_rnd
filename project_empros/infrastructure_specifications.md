# Sentinel Nexus -- Infrastructure & Hardware Specifications

---

## The Problem This Infrastructure Solves

### Finding the Needle in the Needle Stack

Modern enterprise networks don't generate noise with a signal hidden inside it. They generate **signals that look like noise**, at machine speed, across every layer of the stack simultaneously. At 50,000 endpoints, a single hour of operation produces hundreds of millions of telemetry events -- and a determined adversary has already learned to blend every observable into exactly what the environment expects to see.

Traditional SIEMs were built for a different era: they correlate discrete log events against static rules, written by security researchers, after the threat was already documented somewhere else. This architecture fails structurally against:

- **Living-off-the-land (LotL)**: attackers using signed system binaries whose executions are individually indistinguishable from administration
- **Low-and-slow campaigns**: months of sub-threshold activity that never crosses any single alert rule
- **Behavioural blending**: C2 beacons tuned to match the statistical profile of legitimate SaaS traffic
- **Cross-tier pivots**: initial access via a phishing document, privilege escalation via a kernel CVE, lateral movement via a misconfigured service account -- no single tier sees the full chain

Sentinel Nexus was designed from the ground up to solve this. Not by writing more rules, but by **mathematically modelling normal** at every layer of the network simultaneously, then deploying a sovereign AI swarm to autonomously investigate deviations before a analyst would have finished reading the first alert.

---

## What Is Being Collected and Why

### The Complete Telemetry Universe

Sentinel Nexus ingests and correlates telemetry from every observable plane of an enterprise environment. Each plane has a distinct signal model; the AI swarm reasons across all of them simultaneously.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     TELEMETRY COLLECTION PLANES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ENDPOINT (Host)                     NETWORK                                │
│  ├─ Windows Sysmon / XDR Dev         ├─ Full L7 session tap (42 fields)     │
│  │   Process trees, registry,        │   JA3 fingerprints, TLS certs,       │
│  │   DLL loads, named pipes,         │   byte ratios, inter-arrival CV,     │
│  │   memory injection events,        │   DNS tunnelling entropy             │
│  │   ETW tamper attempts             │                                      │
│  │                                   ├─ Linux C2 sensor (eBPF)              │
│  ├─ Windows DeepSensor (UEBA)        │   Flow-level: outbound_ratio,        │
│  │   Score, entropy, velocity        │   packet_size stats, JA3,            │
│  │   (4D windows_math vector)        │   DGA entropy, beacon CV             │
│  │                                   │   (8D c2_math vector)                │
│  ├─ Linux Sentinel (eBPF/auditd)     │                                      │
│  │   Syscall chains, UID trans.,     ├─ Suricata IDS (ET Open rules)        │
│  │   namespace ops, container        │   Rule-based alerts with JA3,        │
│  │   escape chains                   │   file hashes, port scan sigs        │
│  │   (5D sentinel_math vector)       │                                      │
│  │                                   └─ Network tap aggregate               │
│  └─ Trellix ENS log parser               (8D network_tap vector)            │
│      Detections, blocks, DLP                                                │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CLOUD / VIRTUAL INFRASTRUCTURE      IDENTITY & ACCESS                      │
│  ├─ AWS CloudTrail                   ├─ Azure Entra ID / AAD                │
│  │   IAM role chains, API velocity,  │   Impossible travel, MFA bypass,     │
│  │   AssumeRole sequences,           │   SPN abuse, OAuth consent           │
│  │   S3 bucket ACL mutations         │   phishing, token persistence        │
│  │                                   │   (5D cloud_flow vector)             │
│  ├─ AWS GuardDuty                    │                                      │
│  │   Pre-triaged findings: Tor,      ├─ AWS IAM anomalies                   │
│  │   credential exfil, C2,           │   Principal chains, cross-account    │
│  │   cryptomining signals            │   assume-role, secret access         │
│  │                                   │                                      │
│  ├─ Azure Activity Logs              └─ GCP Audit / SCC                     │
│  │   RunCommand abuse, RBAC              SA key exports, VPC flow,          │
│  │   escalation, snapshot abuse          privilege escalation chains        │
│  │                                                                          │
│  └─ VMware vSphere syslog                                                   │
│      ESXi SSH, vCenter snapshot                                             │
│      abuse, NSX lateral movement                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why Mathematical Vectors, Not Rules

Every sensor in Sentinel Nexus reduces its telemetry to a **compact mathematical vector** before the AI swarm ever sees it. This is the architectural foundation that makes the system evasion-resistant:

- **`windows_math` (4D)**: command entropy, parent-child anomaly score, integrity level, velocity -- captures whether a process *behaves* like malware regardless of its name
- **`sentinel_math` (5D)**: Shannon entropy, execution velocity, tuple rarity, path depth, anomaly score -- captures Linux process chains that deviate from their own historical baseline
- **`c2_math` (8D)**: outbound ratio, packet size statistics, inter-arrival coefficient of variation, payload entropy, DGA signal, JA3 hash novelty -- captures whether a network flow *beacons* regardless of what domain it uses
- **`cloud_flow` (5D)**: interval regularity, CV, outbound ratio, packet size mean, threat score -- captures cloud API call patterns that deviate from service-account norms
- **`network_tap` (8D)**: full 42-field L7 session statistics -- captures session-level behavioral signatures across the entire protocol stack

These vectors are stored in **Qdrant's HNSW indices** and searched with cosine similarity. An attacker who successfully mimics one dimension (e.g., legitimate-looking DNS queries) still gets caught by the other seven dimensions of the `c2_math` vector space. The math doesn't care what the domain name is.

---

## The Machine Learning and UEBA Architecture

### Three-Tier Autonomous Detection

```
TIER 0: Mathematical Anomaly Detection (Model A -- BiLSTM-AE)
  └─ Every network_tap flow scored against a normalised baseline
     Reconstruction error > μ+3σ threshold → anomaly signal
     CPU-only, wire-speed inference, sub-millisecond latency
     Feeds: nettap_expert agent for L7 forensic deep-dive

TIER 1: Vector Space Tripwires (Qdrant HNSW -- worker_qdrant)
  └─ All host + cloud telemetry mapped to 4D/5D/8D math spaces
     HNSW cosine search finds nearest anomalous neighbours
     Zero named threat signatures -- purely behavioural geometry
     Feeds: host_expert, net_expert, cloud_expert agents

TIER 2: Agentic Forensic Investigation (Models B, C, D -- LLM swarm)
  └─ Model B: Network adversarial pattern classifier (Mistral-Small-3.1-24B)
       128k context window -- holds full session corpus for L7 forensics
     Model C: Spatial endpoint expert (Llama-3.1-8B + SpatialProjector)
       Sensor vectors spliced directly into latent space at <|spatial_vector|>
       Reasons about host behaviour WITH mathematical proof, not just text
     Model D: SOAR critic / blast radius evaluator (Gemma-3-4B DPO)
       DisruptionIndex computation -- governs containment scope
       Fails CLOSED: unreachable → demote to manual_review_required
```

### UEBA -- User and Entity Behaviour Analytics

The mathematical vector system is the UEBA layer. Every entity in the fleet -- each workstation, server, service account, cloud principal, and network segment -- accumulates a **rolling behavioural baseline** in the Qdrant vector store. Anomaly detection is not threshold-based; it is **geometric distance** from that entity's own historical cluster.

This means:
- A server that always runs PowerShell scripts scores low on `command_entropy` in its historical cluster. The same server running encoded base64 commands -- even with no known-malicious strings -- produces a vector that falls *outside* its cluster. Qdrant fires before any rule matches.
- A service account that consistently assumes the same IAM roles at the same times has a tight `cloud_flow` cluster. An attacker reusing those credentials from a new IP at an off-hour produces a vector displaced from the cluster centroid. The displacement is the detection.
- A network segment with predictable inter-arrival timing (e.g., NTP, backup jobs) has a tight `c2_math` cluster. A C2 beacon tuned to 30-second jitter with CV=0.04 sits geometrically close to zero-jitter automated traffic but still outside the organic cluster for that segment.

The model trains continuously on operator feedback via **RLHF** -- when an analyst dismisses a false positive, that decision is recorded as a DPO preference pair and the critic model learns to widen its containment threshold for that behavioural class. The system gets sharper with every investigation.

---

## The MLOps Pipeline -- What It Learns From

The training corpus is not sourced from the internet. It is built entirely from:

1. **Synthetic behavioral corpus** (offline, no S3 required) -- 9 MITRE ATT&CK tactic phases, 175 tool classes, 2,100 SFT records with 3-axis chain-of-thought reasoning. Each record teaches the model WHY a behavioral signal is adversarial -- not just that it is.

2. **Live sensor telemetry from S3 cold storage** -- Track 6 in the spool pipeline matches behavioral S3 queries against real Parquet from the fleet. The model trains on actual observed attack patterns from the environment, not curated internet datasets.

3. **Operator RLHF feedback loop** -- Every analyst decision (confirm, dismiss, escalate) produces a DPO preference pair. The critic model's blast-radius evaluation improves with every closed investigation. False positives become hard negatives in the next training cycle.

4. **Windows and Linux exploitation behavioral corpus** -- 10 Windows exploitation chains (CVE-specific, behavioral-only) + 10 Linux kernel exploitation chains teach the model to detect the full exploitation sequence, not just the final privilege escalation event.

5. **Golden dataset with spatial proxy vectors** -- 200 records covering all 12 source types with 384D embedding vectors as training bootstraps while the real sensor pipeline populates the named vector spaces.

The MLOps pipeline is **completely sovereign and air-gapped**. No model weights, training data, or investigation context ever leaves the environment. `TRANSFORMERS_OFFLINE=1` and `HF_DATASETS_OFFLINE=1` are set in every inference container.

---

## The Agentic Swarm -- What It Does With the Data

When a vector-space anomaly or mathematical baseline breach fires, the LLM Hunter daemon constructs a **Directed Acyclic Graph (DAG)** of specialised agents, each with domain expertise and tool access:

```
Tier-3 Incident Commander (supervisor.py)
  │
  ├─ net_expert.py        ← C2 flows, IDS alerts, DGA patterns
  │   Tools: DuckDB S3 Parquet queries, Suricata correlation, ti_lookup
  │
  ├─ nettap_expert.py     ← Full L7 session forensics (Model A cross-ref)
  │   Tools: 42-field session analysis, JA3, TLS cert chain, geo-ASN
  │
  ├─ host_expert.py       ← Windows/Linux process forensics
  │   Tools: DuckDB temporal pivot, Sysmon event correlation, YARA
  │
  ├─ cloud_expert.py      ← Cloud API chain analysis
  │   Tools: CloudTrail query, IAM role graph, GuardDuty enrichment
  │
  └─ critic.py            ← Adversarial red-team skeptic
      Challenges every conclusion -- requires behavioral proof on all 3 axes
      before recommending containment

All agents share:
  ├─ ti_lookup.py         ← Internal OpenCTI (air-gapped) + external providers
  ├─ qdrant_search.py     ← Historical vector similarity search
  ├─ entity_manager.py    ← Entity dedup, blast radius tracking
  └─ sanitizer.py         ← Prompt injection defence on all IOC strings

Output → response.py → SOAR payload → n8n → containment action
                      → RLHF feedback → next training cycle
```

The swarm does not alert analysts and wait. It **autonomously investigates, builds an attack graph, computes blast radius, and produces a containment recommendation with evidence** -- all before an on-call analyst would have context-switched to the alert. Analyst review is required only when DisruptionIndex exceeds 0.5 (critical infrastructure) or the critic model returns `manual_review_required`.

---

## The Operational Stack -- Closing the Loop

The full incident lifecycle runs without analyst intervention in normal cases:

```
Anomaly detected → Swarm investigates → Critic evaluates blast radius
      ↓                                           ↓
 CONFIRM_QUARANTINE ← DisruptionIndex < 0.5      MANUAL_REVIEW
      ↓
n8n SOAR workflow → EDR isolate / FW block / Cloud containment
      ↓
Operator reviews outcome → RLHF feedback → DPO training pair
      ↓
Next critic training cycle → tighter decisions → fewer false positives
```

The operations stack provides:
- **n8n SOAR engine** -- webhook-driven containment workflows for AWS Lambda, Azure Runbook, GCP Cloud Function, and direct EDR API
- **Open WebUI operator terminal** -- sovereign inference gateway routing to all 4 models + frontier models (Claude, GPT-4) for analyst augmentation
- **Authentik zero-trust SSO** -- per-analyst OAuth2 sessions with RBAC; operator context injected into every investigation
- **Prometheus + Grafana** -- model inference latency, Qdrant search P99, NATS consumer lag, GPU utilization, investigation throughput
- **RLHF circuit breaker** -- if >50 global operator overrides or >10 per operation type in a training window, the pipeline halts and requires manual review before the next DPO cycle

This is a system that gets **better at finding adversaries the longer it runs**, in a closed loop, without sending data to any external service.

---

> [!NOTE]
>
> The following requirements are for 40-50k endpoint environments (enterprise).
>
> For smaller enclaves, the majority of costs are driven by hardware provisioning -- specifically GPU compute (MLOps) and large-scale telemetry data lakes.
>
> Probably why all these data centers are being built...
>
> Be advised, you may incur additional charges for energy drinks, snacks, and espresso machines.

---

## 0. Telemetry Volume Analysis -- The Firehose Math

Before specifying hardware, the throughput numbers must be established.
Everything below is sized around the **Medium (50K endpoint)** production target.

### Deployment Tiers

| Tier | Endpoints | Windows | Linux | Network Tap | Use Case |
|---|---|---|---|---|---|
| **Small** | 5,000 | 3,500 | 1,500 | 1 Gbps | Pilot / lab |
| **Medium** | 50,000 | 35,000 | 15,000 | 10 Gbps | Production |
| **Large** | 500,000 | 350,000 | 150,000 | 100 Gbps | Enterprise |

### Event Rate Model (Medium Tier -- 50K endpoints)

```
Sensor              Endpoints   Events/ep/min   Events/min       Parquet/event   MB/min
─────────────────────────────────────────────────────────────────────────────────────────
sysmon_sensor         35,000         100         3,500,000          500 B         1,750
windows_deepsensor    35,000          20           700,000        1,000 B           700
windows_c2            35,000         200         7,000,000          300 B         2,100
linux_sentinel        15,000          50           750,000        2,000 B         1,500
linux_c2              15,000         500         7,500,000          300 B         2,250
network_tap              n/a       50,000 flows/min (sampled)       400 B           200
─────────────────────────────────────────────────────────────────────────────────────────
TOTAL COMPRESSED PARQUET (ZSTD 5:1 compression applied above)              ~8,500 MB/min
SUSTAINED INGRESS                                                           ~142 MB/sec
PEAK BURST (3× sustained)                                                   ~425 MB/sec
```

### Derived Storage Requirements (Medium Tier)

```
Hot storage (NATS JetStream, 24h retention):    142 MB/s × 86,400s = 12.3 TB/day
JetStream 3-node cluster target:                12.3 TB × 3 replicas = 36.9 TB NVMe

Cold archive (S3/MinIO, 90-day retention):      12.3 TB/day × 90 = 1,107 TB
  → AWS S3 Intelligent-Tiering (preferred for cloud deployments)
  → On-prem MinIO: 200+ TB usable, tiered HDD + NVMe

Qdrant vector hot index (30-day rolling):
  Anomalous events (≈0.01% of traffic):         ~10M vectors total
  Memory per vector (HNSW M=16):                ~600 bytes
  Total Qdrant RAM required:                    ~6 GB vectors + 100 GB payload
  Minimum RAM per Qdrant node (3-node):         256 GB (index + payload + OS buffer)

MLOps training dataset (rolling 180 days):      500 GB – 5 TB Parquet
Model weights (A+B+C+D adapters):               150 – 500 GB NVMe

S3 request rate at sustained ingress:           ~500,000 PUT/day (worker_s3_archive)
NATS message throughput:                        ~200,000 messages/sec peak
```

### What "Potentially Tons of Data" Really Means

| Component | Bottleneck | Relief |
|---|---|---|
| Parquet serialization | CPU (ZSTD compression) | Parallel workers, NUMA pinning |
| NATS JetStream write | NVMe sequential IOPS | 3-node cluster, NVMe striping |
| Qdrant insert rate | CPU (HNSW graph update) | Dedicated nodes, batched inserts |
| S3 archive upload | Network + CPU (multipart) | 25 GbE uplinks, worker concurrency |
| DuckDB MLOps scans | RAM + NVMe bandwidth | 512+ GB RAM, local NVMe scratch |

---

## 1. Physical Network Topology

### Leaf-Spine Fabric (On-Premises)

```
         ┌──────────────────────────────────────────┐
         │         SPINE SWITCHES (2× 100GbE)       │
         │         100GbE interconnect (ECMP)       │
         └────┬──────────┬────────────┬─────────────┘
              │          │            │
       ┌──────┴──┐  ┌────┴────┐  ┌───┴─────┐
       │ LEAF-A  │  │ LEAF-B  │  │ LEAF-C  │  ← 48× 25GbE downlinks
       │ 100GbE  │  │ 100GbE  │  │ 100GbE  │    2× 100GbE uplinks each
       │ uplinks │  │ uplinks │  │ uplinks │
       └─────────┘  └─────────┘  └─────────┘
            │              │            │
    ┌───────┴───┐  ┌───────┴─────┐ ┌────┴────────┐
    │NATS+Qdrant│  │GPU+Analytics│ │MinIO+Workers│
    │  BARE     │  │  BARE METAL │ │ BARE METAL  │
    │  METAL    │  │             │ │             │
    └───────────┘  └─────────────┘ └─────────────┘
                         │
                  ┌──────┴──────┐
                  │  VMware ESXi│  ← VMs: ingress, redis,
                  │  Cluster    │    workers, TI, management
                  └─────────────┘
```

### VLAN Segmentation

| VLAN | ID | Subnet | MTU | Purpose |
|---|---|---|---|---|
| `NEXUS-INGRESS` | 10 | 10.0.10.0/24 | 1500 | HAProxy + Rust Axum gateway (internet-facing) |
| `NEXUS-BUS` | 20 | 10.0.20.0/24 | **9000** | NATS JetStream cluster (jumbo for throughput) |
| `NEXUS-CACHE` | 30 | 10.0.30.0/24 | 9000 | Redis dedup + alert queue |
| `NEXUS-VECTOR` | 50 | 10.0.50.0/24 | **9000** | Qdrant -- high-bandwidth vector insert/search |
| `NEXUS-WORKERS` | 60 | 10.0.60.0/24 | 9000 | Rust workers (S3, rules, SOAR, RLHF) |
| `NEXUS-STORAGE` | 70 | 10.0.70.0/24 | **9000** | MinIO on-prem S3 (max throughput critical) |
| `NEXUS-ANALYTICS` | 80 | 10.0.80.0/24 | 9000 | LLM hunter + MLOps training node |
| `NEXUS-INFERENCE` | 85 | 10.0.85.0/24 | 9000 | GPU inference cluster |
| `NEXUS-TI` | 90 | 10.0.90.0/24 | 1500 | OpenCTI threat intel (isolated) |
| `NEXUS-MGMT` | 100 | 10.0.100.0/24 | 1500 | Prometheus, Grafana, Ansible, IPMI |
| `NEXUS-SENSOR` | 110 | 10.0.110.0/24 | 1500 | Sensor endpoints (dedicated, ACL-restricted) |

### Network Hardware Requirements

**Spine switches (2× for HA):**
- 32× 100GbE QSFP28 ports minimum
- ECMP load balancing
- Recommended: Arista 7280, Cisco Nexus 9332, or Juniper QFX5200

**Leaf switches (3-4× for scale):**
- 48× 25GbE SFP28 server-facing downlinks
- 8× 100GbE QSFP28 uplinks to spine (active-active LACP)
- Recommended: Arista 7050CX3, Cisco Nexus 93180YC-FX

**Edge/Internet:**
- Dual 10GbE uplinks (bonded) minimum; 25GbE preferred
- Sensor traffic is inbound only -- bandwidth determined by fleet size
- At 50K endpoints: 5-50 Mbps average (sensors batch compress)

---

## 2. Per-Node Hardware Specifications

### Deployment Decision Matrix: Bare Metal vs VM

| Node Group | Decision | Reason |
|---|---|---|
| Ingress (HAProxy + Axum) | **VM** | Network-bound; hypervisor SR-IOV mitigates overhead |
| NATS JetStream | **BARE METAL mandatory** | 12+ TB NVMe, 200K msg/sec; hypervisor adds unacceptable jitter |
| Redis | **VM** | Pure in-memory; I/O is checkpoint-only |
| Qdrant | **BARE METAL strongly preferred** | Memory bandwidth to serve HNSW; avoid NUMA penalty |
| Rust Workers | **VM** | CPU-bound compute; no I/O requirement |
| Analytics / MLOps | **BARE METAL mandatory** | DuckDB Parquet scans need raw NVMe + 512 GB+ RAM |
| GPU Inference | **BARE METAL mandatory** | PCIe × 16 bandwidth, NVLink, 3kW+ power draw |
| MinIO Storage | **BARE METAL preferred** | Sequential throughput to HDDs; hypervisor limits IOPS |
| TI (OpenCTI) | **VM** | Moderate Elasticsearch workload |
| Management | **VM** | Prometheus TSDB, light traffic |

---

### Node 1–2: Ingress (HAProxy + Rust Axum Gateway)
**Count: 2 (active-active)**
**Deployment: VM (VMware ESXi) or small bare metal**
**Subnet: VLAN 10 -- 10.0.10.10–11**

```
CPU:      16 vCPU (4 physical cores, 2× hyperthreading) -- or 8 dedicated cores
RAM:      32 GB (HAProxy + Axum + Rust ingress workers)
NIC:      2× 25GbE (LACP bonded) -- primary; 1× 1GbE for IPMI/OOB
Storage:  500 GB NVMe OS + temp (no local data -- stateless)
OS disk:  NVMe (not HDD -- kernel TLS requires fast syscall path)

Rationale:
  - 425 MB/sec peak ingress saturates ~3.4 Gbps -- well within 25GbE
  - SSL/TLS termination is CPU-bound; 16 vCPU handles 50K TLS sessions
  - Rust Axum + kernel bypass (io_uring) minimizes per-request overhead
  - Stateless -- no local persistence; all data forwarded to NATS

NIC config:
  Bond0 (25GbE):    external-facing, sensor telemetry ingress
  Bond1 (25GbE):    internal mesh to NATS/workers
```

**What MUST be installed bare metal here (if not VM):**
- OS: Debian 12 Bookworm (hardened image per common_hardening role)
- Kernel: 6.6+ LTS with io_uring, TLS kTLS enabled
- No JVM, no Python interpreters -- Rust binary only

---

### Node 3–5: NATS JetStream Cluster
**Count: 3 (quorum cluster -- never even number)**
**Deployment: BARE METAL mandatory**
**Subnet: VLAN 20 -- 10.0.20.10–12**

```
CPU:      AMD EPYC 9354P (32 cores, 128 MB L3)
          -- or Intel Xeon Gold 6414U (32 cores)
          Single-socket preferred; dual-socket wastes money on I/O node
RAM:      256 GB DDR5-4800 ECC (8× 32 GB DIMMs)
          JetStream consumer state + pending message buffers in RAM

NIC:      2× 25GbE SFP28 (LACP bond to leaf switch) -- internal mesh only
          1× 1GbE -- IPMI out-of-band management

NVMe:     8× 4 TB NVMe Gen4 (U.2 or E1.S form factor)
          ├── 4× in RAID10 → 8 TB usable JetStream store (write path)
          └── 4× in RAID10 → 8 TB usable JetStream replay / overflow
          Total usable per node: 16 TB NVMe
          Sequential write: 14–20 GB/sec aggregate (4× Samsung PM9A3)

OS disk:  2× 1 TB NVMe RAID1 (OS only -- separate from JetStream pool)

Power:    2× 1600W PSU (redundant)
Form:     2U rackmount

Required JetStream performance at 50K endpoints:
  Sustained write: 142 MB/s × 3 replicas = 426 MB/s per leader
  With 8× NVMe RAID10: ~7 GB/s available → 16× headroom
  24-hour retention: 12.3 TB per node -- 16 TB provides comfortable buffer

Bare metal requirements:
  - Direct NVMe without hypervisor virtualization layer
  - NUMA locality: NVMe controllers on same socket as NATS process
  - IRQ affinity: NATS Rust process pinned to CPU cores 0-15
  - Huge pages: 64 GB reserved for JetStream page cache
  - Storage scheduler: none (NVMe bypasses elevator)
```

---

### Node 6–7: Redis Cluster
**Count: 2 (primary + replica; add 4 for Redis Cluster mode at scale)**
**Deployment: VM acceptable**
**Subnet: VLAN 30 -- 10.0.30.10–11**

```
CPU:    8 vCPU (Redis is largely single-threaded; I/O threads use remaining)
RAM:    128 GB (Redis in-memory dataset + AOF buffer)
        Working set at 50K endpoints:
          dedup ring:      ~2 GB (50K × 40 bytes × 1000 entries)
          alert queue:     ~10 GB (pending SOAR decisions)
          rule cache:      ~5 GB (Sigma rule compiled state)
          rate limit keys: ~1 GB
          Total:           ~20 GB hot; 128 GB provides 6× headroom

NIC:    1× 10GbE (Redis throughput is bounded by CPU, not network)
SSD:    500 GB NVMe (RDB snapshots + AOF write)
        AOF write rate at 50K endpoints: ~50 MB/s → NVMe (not HDD)

Redis config:
  maxmemory: 96gb
  maxmemory-policy: allkeys-lru
  save: 60 1  (RDB every 60s if ≥1 key changed)
  appendonly: yes
  appendfsync: everysec
  hz: 100

Do NOT run Redis on HDD -- AOF fsync at everysec requires <10ms latency
```

---

### Node 8–10: Qdrant Vector Database Cluster
**Count: 3 (distributed shard mode)**
**Deployment: BARE METAL strongly preferred (VM acceptable if NUMA-aware)**
**Subnet: VLAN 50 -- 10.0.50.10–12**

```
CPU:    AMD EPYC 9554P (64 cores, 256 MB L3, 12-channel DDR5)
        -- memory bandwidth is the critical metric, not core count
        -- 12-channel DDR5 provides 460 GB/s bandwidth (HNSW graph traversal)
RAM:    512 GB DDR5-4800 ECC (16× 32 GB DIMMs) per node
        HNSW index memory model:
          50M vectors × 600 bytes/vector (M=16 graph) = 30 GB index
          Payload storage per vector: 2 KB avg = 100 GB
          OS + Rust runtime + MMAP overhead: 50 GB
          Total: ~180 GB hot; 512 GB provides index doubling headroom

NVMe:   4× 4 TB NVMe Gen4 RAID10 → 8 TB usable (vector payload on-disk)
        On-disk payload for cold vectors not in MMAP cache
        IOPS: 800K random read IOPS (Samsung PM9A3) -- needed for KNN search

NIC:    2× 25GbE (LACP) -- high-bandwidth vector insert bursts during incidents

OS:     Bare metal advantage: kernel hugepages for MMAP, no NUMA crossing

Qdrant configuration:
  [storage]
  on_disk_payload: true          # Payload on NVMe, index in RAM
  hnsw_index:
    m: 16                        # Graph connections (higher = better recall)
    ef_construct: 200            # Build-time search depth
    full_scan_threshold: 10000   # Below this: brute-force (faster for small)

  [service]
  max_request_size_mb: 256
  grpc_port: 6334                # gRPC for worker_qdrant batch inserts

  Performance targets at 50K endpoints:
    Insert rate: 50,000 vectors/sec per node (batched)
    Search latency P99: <10ms at ef=128
    Concurrent searches: 1,000 (supervisor + swarm agents)
```

---

### Node 11–14: Rust Worker Fleet
**Count: 4 (scales horizontally)**
**Deployment: VM acceptable**
**Subnet: VLAN 60 -- 10.0.60.10–13**

```
CPU:    32 vCPU (Rust async workers are CPU-bound; NATS consumer groups)
RAM:    128 GB per node
        worker_qdrant: 8 GB (Arrow batch buffers)
        worker_rules:  16 GB (Sigma rule state + Aho-Corasick automata)
        worker_soar:   8 GB (SOAR payload + retry queue)
        worker_rlhf:   8 GB (preference pair staging)
        worker_s3:     32 GB (Parquet batching before S3 multipart upload)
        OS + other:    56 GB buffer

NVMe:   1 TB per node (local Parquet staging before S3 upload)
        worker_s3_archive batches 500 rows before upload -- needs fast scratch

NIC:    10GbE (NATS consumer + S3 upload combined ~200 MB/s max)

Do NOT share a VM host with NATS or Qdrant -- CPU contention degrades latency
```

---

### Node 15: Analytics / MLOps Training Node
**Count: 1 (scale to 2 for redundancy in large deployments)**
**Deployment: BARE METAL mandatory**
**Subnet: VLAN 80 -- 10.0.80.10**

This is the most memory-intensive CPU node. DuckDB scans over S3 Parquet at
training time require the ENTIRE dataset to fit in NVMe-backed scratch and large
portions to fit in RAM. The LLM Hunter agentic swarm also runs here.

```
CPU:    AMD EPYC 9654P (96 cores, 384 MB L3) -- or dual EPYC 9354 (64 cores)
        MLOps reason: SFT training uses DataLoader workers (1 per CPU core)
        LLM Hunter reason: concurrent Python agents (10-30 simultaneous)
        DuckDB reason: parallelism = min(cores, Parquet row-groups)

RAM:    512 GB DDR5-4800 ECC (16× 32 GB DIMMs) MINIMUM
        768 GB preferred for large fleet (1 TB Parquet scan in memory):
          DuckDB working set:        256 GB (Parquet columnar scan buffer)
          PyTorch SFT training:      128 GB (model + gradient + optimizer state)
          LLM Hunter swarm:          64 GB (10 agents × 6 GB Python heap each)
          MLOps data pipeline:       64 GB (safetensors, Arrow batches)
          OS + cache:                64 GB

NVMe:   8× 4 TB NVMe Gen4 RAID0 → 32 TB usable local scratch
        ├── 16 TB: DuckDB S3 Parquet cache (avoids re-download on retrain)
        ├── 8 TB:  MLOps staging (JSONL, safetensors, model checkpoints)
        └── 8 TB:  OS + Python venvs + Docker layer cache

NIC:    1× 100GbE (S3 data pull during training: need >10 GB/s for large scans)
        1× 25GbE (internal NATS/Redis/Qdrant traffic)

GPU (optional but recommended for smaller training runs):
        2× NVIDIA A100 40GB PCIe (for Model A training + small LoRA)
        OR: offload all GPU training to Node 16

Power:  2× 2000W PSU (redundant)

What runs bare metal here (mandatory):
  - DuckDB 0.10+ with Parquet extension (requires direct NVMe access)
  - Python 3.12 with PyTorch, Transformers, PEFT, TRL
  - MLOps pipeline scripts (01_spool through 04_merge)
  - LLM Hunter daemon (LangChain/LangGraph agent orchestrator)
  - serve_baseline.py (Model A NATS consumer -- CPU only)

What CANNOT be in a VM here:
  - DuckDB S3 Parquet scans (hypervisor NVMe virtualization kills throughput)
  - PyTorch training (RAM bandwidth is halved through hypervisor)
```

---

### Node 16: GPU Inference Cluster
**Count: 1 physical host (4× A100 80GB -- scale to 2 hosts for HA)**
**Deployment: BARE METAL mandatory**
**Subnet: VLAN 85 -- 10.0.85.10**

```
GPU:    4× NVIDIA A100 80GB SXM4
        Connected via NVLink (600 GB/s bidirectional between GPUs)
        NVLink is MANDATORY for Model B tensor-parallel inference

GPU Allocation:
  GPU 0-1 (160 GB VRAM):  vllm-network.service  -- Model B (Mistral-Small 24B)
    QLoRA NF4 quantized: 24B × 0.5 bytes = 12 GB weights
    KV cache at 128k context, batch=4: ~80 GB
    Total: ~92 GB → fits in 160 GB with 70 GB safety margin

  GPU 2-3 (160 GB VRAM):  vllm-inference.service -- Model C (Llama-3.1-8B)
                           vllm-critic.service    -- Model D (Gemma-3-4B)
    Model C fp16: 8B × 2 bytes = 16 GB weights + KV cache = ~80 GB
    Model D NF4: 4B × 0.5 = 2 GB + cache = ~16 GB
    Total: ~96 GB → fits in 160 GB with 64 GB safety margin

CPU:    Dual Intel Xeon Platinum 8568Y+ (48 cores each = 96 total)
        PCIe 5.0 × 16 per GPU (NVMe-bound host memory feeding GPU)

RAM:    768 GB DDR5-5600 ECC
        vLLM PagedAttention KV cache overflow: 128 GB per model pair
        Python process + HF cache + CUDA context: 128 GB
        OS + driver: 32 GB
        Total needed: ~512 GB; 768 GB provides headroom

NVMe:   4× 4 TB NVMe Gen5 PCIe → 8 TB RAID10
        Model weights: ~200 GB (all 4 models + adapters)
        HF cache: 200 GB
        vLLM swap space: 1 TB (KV cache overflow to NVMe)

NIC:    2× 100GbE (GPU inference requests from LLM Hunter via HTTP)

Power:  4× A100 SXM4 × 400W = 1600W GPU
        CPU + RAM + NVMe: ~800W
        Total: 2400W steady-state
        Require: 2× 2400W PSU + 30A/240V circuits

Cooling: Direct liquid cooling (DLC) recommended for A100 SXM4
         Air cooling requires 30+ CFM front-to-back airflow

Why bare metal ONLY:
  - PCIe GPU passthrough is available but adds latency (10-20ms per call)
  - NVLink does NOT pass through hypervisors -- Model B tensor-parallel breaks
  - GPU power management requires BIOS + DCGM daemon access

ALTERNATIVE for budget deployments:
  2× NVIDIA H100 NVL (94 GB) instead of 4× A100 SXM4
  H100 NVL has higher memory bandwidth (4.8 TB/s vs 2.0 TB/s per A100)
  Reduces node count from 4 GPUs to 2 while improving throughput 2×
```

---

### Node 17: MinIO On-Prem Storage
**Count: 1 node (single-node for <50 TB; 4-node distributed for 50 TB+)**
**Deployment: BARE METAL preferred**
**Subnet: VLAN 70 -- 10.0.70.10**

```
Single-node (up to 50 TB, ≤10K endpoints):
  CPU:    16 cores (I/O scheduling, ZSTD decompression)
  RAM:    128 GB (read-ahead buffer; MinIO recommends 1 GB per 1 TB data)
  NVMe:   2× 4 TB NVMe RAID1 (OS + hot metadata index)
  HDD:    12× 20 TB SATA HDD (RAID6 → 200 TB usable)
  NIC:    2× 25GbE (LACP)

4-node distributed (50–500 TB, 50K+ endpoints):
  Per node:
    CPU:    32 cores
    RAM:    256 GB
    NVMe:   4× 4 TB NVMe RAID10 → 8 TB (hot tier / metadata)
    HDD:    16× 20 TB SAS HDD JBOD → 320 TB raw per node
            MinIO erasure code (EC:4+2) → 208 TB usable per node
  4 nodes total usable: 832 TB
  Sequential write: 8 GB/s aggregate (HDD saturated with 16 drives)

  IMPORTANT: MinIO distributed mode requires all nodes to have IDENTICAL
  disk layouts. Mismatched drives break EC parity.

For AWS (no on-prem MinIO needed):
  Use S3 with S3 Intelligent-Tiering
  Lifecycle policy: move to Glacier after 30 days (forensic archive)
  Cost at 50K endpoints for 90 days: ~$25,000–$45,000/month
```

---

### Node 18: TI -- OpenCTI Stack
**Count: 1**
**Deployment: VM acceptable**
**Subnet: VLAN 90 -- 10.0.90.10**

```
CPU:    16 vCPU
RAM:    64 GB (Elasticsearch heap: 32 GB; OpenCTI Node.js: 16 GB; Redis+RabbitMQ: 8 GB)
NVMe:   2 TB (Elasticsearch index + MinIO STIX file storage)
NIC:    10GbE (TI lookups are read-heavy, low bandwidth)

Elasticsearch heap (critical):
  ES_JAVA_OPTS=-Xms32g -Xmx32g
  Do NOT exceed half of physical RAM (OS file cache uses the rest)

OpenCTI at production scale:
  MITRE ATT&CK bundle: ~1 GB Elasticsearch index
  Custom STIX bundles (operator-curated): 5–50 GB over 12 months
  Connector workers: 3 replicas × 512 MB heap = 1.5 GB
```

---

### Node 19: Management / Observability
**Count: 1**
**Deployment: VM**
**Subnet: VLAN 100 -- 10.0.100.10**

```
CPU:    8 vCPU
RAM:    32 GB (Prometheus TSDB: 16 GB; Grafana: 4 GB; Ansible control: 8 GB)
NVMe:   500 GB (Prometheus 15-day TSDB retention at 50K endpoints ≈ 200 GB)

Prometheus scrape config at 50K endpoints:
  Scrape interval: 15s
  Targets: ~20 (all node_exporters, NATS monitoring, Qdrant, etc.)
  Metrics/scrape: ~5,000 average
  TSDB block size: ~12 GB/day at this cardinality
  15-day local retention: ~180 GB → 500 GB NVMe is sufficient

  Remote write to Thanos/Mimir for long-term retention (optional)
```

---

## 3. VMware Cluster Sizing (Hosts for VMs)

The VM-hosted nodes (ingress, Redis, workers, TI, management) require:

```
Total VM RAM required:
  2× ingress VMs:      2 × 32 GB  =  64 GB
  2× Redis VMs:        2 × 128 GB = 256 GB
  4× worker VMs:       4 × 128 GB = 512 GB
  1× TI VM:            1 × 64 GB  =  64 GB
  1× management VM:    1 × 32 GB  =  32 GB
  ────────────────────────────────────────
  Total VM RAM:                     928 GB

VMware overcommit ratio (safe for mixed workloads): 1.25×
Physical RAM needed: 928 × 1.25 = 1,160 GB

Recommended ESXi cluster: 3× hosts (N+1 HA):
  Per host: 512 GB DDR5 ECC, 48 vCPU (dual 24-core Xeon or EPYC)
  3 hosts: 1,536 GB total → 1,160 GB VMs + 376 GB hypervisor reserve

  ESXi host NIC: 2× 25GbE (VM traffic) + 1× 10GbE (vMotion) + 1GbE (IPMI)
  Shared NVMe storage: either SAN/NFS or local NVMe per host
  vSAN (optional): 3× 4 TB NVMe per host → 36 TB raw shared storage for VMs
```

---

## 4. AWS Cloud Instance Specifications

### Instance Selection Matrix

> **Note:** The existing Terraform uses undersized instances (c6i.large, r6i.large).
> The following are the correct production-grade specs.

| Node Group | Current (wrong) | Correct Instance | Count | vCPU | RAM | Rationale |
|---|---|---|---|---|---|---|
| Ingress | c6i.large | **m7i.4xlarge** | 2 | 16 | 64 GB | TLS offload needs RAM for connection state |
| NATS | i4i.xlarge | **i4i.8xlarge** | 3 | 32 | 256 GB | 30 TB NVMe, 256 GB RAM for JetStream |
| Redis | r6i.large | **r7i.4xlarge** | 2 | 16 | 128 GB | In-memory dataset at 50K endpoints |
| Qdrant | r6i.2xlarge | **r7iz.16xlarge** | 3 | 64 | 512 GB | Memory bandwidth for HNSW traversal |
| Workers | c6i.xlarge | **c7i.8xlarge** | 4 | 32 | 64 GB | CPU-bound Rust async workers |
| Analytics | r6i.2xlarge | **r7iz.metal-32xl** | 1 | 128 | 1024 GB | DuckDB + PyTorch + LLM Hunter |
| GPU Inference | (missing) | **p4de.24xlarge** | 1 | 96 | 1152 GB | 8× A100 80GB + NVLink |
| MinIO | (use S3) | **S3 Intelligent-Tiering** | -- | -- | -- | Serverless; pay per GB |
| TI | r6i.2xlarge | **r7i.2xlarge** | 1 | 8 | 64 GB | Elasticsearch + OpenCTI |
| Management | t3.large | **t3.xlarge** | 1 | 4 | 16 GB | Prometheus + Grafana + Ansible |

### Critical AWS Instance Details

**NATS -- i4i.8xlarge:**
```
vCPU:  32
RAM:   256 GB
NVMe:  30 TB local NVMe (2× 15 TB, erasure-stripped by NATS JetStream itself)
       i4i series uses Intel Optane P5800X → <20μs latency
Network: 18.75 Gbps → sufficient for 142 MB/s × 3 replicas
EBS:   Not used for JetStream data -- all local NVMe
Cost:  ~$3,500/month per node × 3 = ~$10,500/month for NATS cluster
```

**Qdrant -- r7iz.16xlarge:**
```
vCPU:  64
RAM:   512 GB DDR5
NVMe:  Local (r7iz has NVMe-backed instance storage -- request via storage optimized)
       Or: io2 Block Express EBS: 8× 2 TB gp3 at 16,000 IOPS each
Network: 50 Gbps → sufficient for vector insert + search traffic
Cost:  ~$9,500/month per node × 3 = ~$28,500/month for Qdrant cluster
```

**Analytics -- r7iz.metal-32xl (bare metal instance):**
```
vCPU:  128 (Intel Xeon Sapphire Rapids, no hypervisor penalty)
RAM:   1024 GB DDR5-4800
Storage: io2 Block Express EBS: 8× 4 TB at 256,000 IOPS each (NVMe-equivalent)
Network: 100 Gbps ENA → sufficient for S3 training data pull
EFS:   Mount at /data/shared for MLOps artifacts accessible to inference nodes
Cost:  ~$22,000/month (bare metal pricing)

Alternative if budget constrained:
  r7iz.32xlarge: 128 vCPU, 1024 GB RAM (virtualized)
  Accept 15-20% performance penalty on DuckDB scans
  Cost: ~$18,000/month
```

**GPU Inference -- p4de.24xlarge:**
```
GPU:   8× NVIDIA A100 80GB SXM4 + NVLink
vCPU:  96 (Intel Xeon)
RAM:   1152 GB
NVMe:  8 TB local NVMe
Network: 400 Gbps ENA (EFA enabled for MPI -- useful if expanding to multi-node training)
Cost:  ~$40,000/month On-Demand
       Savings Plan 1yr: ~$26,000/month
       Spot instance (interruption risk): ~$12,000/month (not recommended for inference)

For inference only (not training), ALTERNATIVE:
  g5.12xlarge (4× A10G 24GB): $5,500/month
  Only viable if models fit in 24 GB VRAM (they don't -- Model B at 128k context needs 80 GB)
  → p4de.24xlarge is the correct choice
```

### AWS EBS Volume Specifications

```
NATS nodes:     Use LOCAL NVMe (i4i instance storage -- do NOT use EBS for JetStream)
Qdrant nodes:   io2 Block Express: 8× 2 TB, 64,000 IOPS/volume, 1000 MB/s throughput
Analytics:      io2 Block Express: 8× 4 TB, 256,000 IOPS/volume, 4000 MB/s throughput
Workers:        gp3: 1 TB, 16,000 IOPS, 1000 MB/s (staging buffer)
All OS volumes: gp3: 100 GB, 3,000 IOPS (root)
```

### AWS Networking (Terraform Additions Required)

```hcl
# Enhanced networking -- add to existing main.tf

resource "aws_placement_group" "nexus_cluster" {
  name     = "nexus-cluster-pg"
  strategy = "cluster"  # All instances in same AZ, same rack
  # Enables 100 Gbps between instances instead of 25 Gbps
}

# NATS, Qdrant, analytics, GPU -- all in placement group
# Reduces latency to <100μs within the group

resource "aws_network_interface" "nats_efa" {
  count              = 3
  subnet_id          = module.vpc.private_subnets[count.index % length(module.vpc.private_subnets)]
  interface_type     = "efa"  # Elastic Fabric Adapter
  # EFA gives RDMA-like throughput: 400 Gbps on p4de
}

# Enhanced S3 VPC endpoint (no NAT cost for training data)
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = module.vpc.vpc_id
  service_name = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids = module.vpc.private_route_table_ids
}
```

---

## 5. Network Performance Tuning

### Kernel Parameters (all nodes -- applied by common_hardening role)

```bash
# /etc/sysctl.d/99-nexus-network.conf

# ── TCP/UDP Receive/Send Buffers ───────────────────────────────────────────────
net.core.rmem_max           = 2147483647    # 2 GB max receive buffer
net.core.wmem_max           = 2147483647    # 2 GB max send buffer
net.core.rmem_default       = 134217728     # 128 MB default (NATS/Qdrant benefit)
net.core.wmem_default       = 134217728
net.ipv4.tcp_rmem           = 4096 131072 2147483647
net.ipv4.tcp_wmem           = 4096 131072 2147483647
net.ipv4.udp_mem            = 3145728 4194304 16777216

# ── Connection Handling ────────────────────────────────────────────────────────
net.core.somaxconn          = 65535         # Max connection backlog (ingress nodes)
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog  = 250000       # NIC ring buffer → kernel queue
net.ipv4.tcp_fin_timeout    = 10            # Fast socket reclaim
net.ipv4.tcp_tw_reuse       = 1             # Reuse TIME_WAIT sockets

# ── Jumbo Frame (VLAN 20/30/50/60/70/80/85 -- 9000 MTU) ───────────────────────
# Configure per-interface in /etc/network/interfaces or systemd-networkd
# MTU=9000 must be consistent end-to-end: switch → NIC → bond → VM

# ── NATS and Qdrant: interrupt coalescing (high-throughput nodes) ──────────────
# ethtool -C eth0 rx-usecs 50 tx-usecs 50   (reduce CPU interrupts at cost of latency)
# For ingress (latency-sensitive): rx-usecs 0 (no coalescing -- lowest latency)
```

### CPU Affinity and NUMA Configuration

```bash
# NATS JetStream (3-node bare metal)
# Pin NATS process to NUMA node 0 (where NVMe controllers attach on EPYC 9354)
numactl --cpunodebind=0 --membind=0 nats-server -c /etc/nats/server.conf

# Qdrant (bare metal EPYC 9554P -- single socket, 12-channel DDR5)
# All memory local: no NUMA penalty on single-socket
# But set huge pages for MMAP
echo "vm.nr_hugepages=131072" >> /etc/sysctl.d/99-nexus.conf  # 256 GB hugepages

# Analytics node (dual-socket EPYC -- DuckDB benefits from cross-NUMA)
# DuckDB auto-detects NUMA: no pinning needed; let it use all NUMA domains
# PyTorch training: pin to NUMA node with GPUs

# GPU inference node
# vLLM and HF transformers respect CUDA_VISIBLE_DEVICES
# Ensure NUMA locality: GPUs 0-1 → NUMA node 0; GPUs 2-3 → NUMA node 1
nvidia-smi topo -m  # Verify NVLink topology
```

### NVMe Performance Configuration

```bash
# Applied to all bare-metal nodes with NVMe

# Storage scheduler: none (NVMe has internal queue, elevator wastes cycles)
echo none > /sys/block/nvme0n1/queue/scheduler

# Queue depth (NVMe supports up to 64K per namespace)
echo 1024 > /sys/block/nvme0n1/queue/nr_requests

# Disable power management (max performance)
echo performance > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
nvme set-feature /dev/nvme0 -f 2 -V 0  # Disable power management

# For RAID10 NVMe (NATS nodes)
# mdadm with write intent bitmap disabled (NVMe is fast enough for resync)
mdadm --create /dev/md0 --level=10 --raid-devices=4 \
  /dev/nvme0n1 /dev/nvme1n1 /dev/nvme2n1 /dev/nvme3n1 \
  --bitmap=none --chunk=512  # 512 KB chunks for sequential write
```

### VLANs Requiring Jumbo Frames (MTU 9000)

All internal data-path VLANs benefit from jumbo frames:
- **VLAN 20 (NATS)**: Reduces interrupts on 142 MB/s sustained write
- **VLAN 50 (Qdrant)**: Large vector batches (8D × 10K vectors = 640 KB per insert)
- **VLAN 70 (MinIO)**: Maximizes HDD sequential throughput on large Parquet writes
- **VLAN 80/85 (Analytics/GPU)**: Model inference requests can be >10 MB (128k context)

**Jumbo frames MUST be configured end-to-end**: switch trunk port + server bond + container.
Mixed MTU silently drops packets -- verify with: `ping -M do -s 8972 10.0.20.10`

### Routing (Internal)

```
10.0.0.0/16    → all Nexus nodes via internal routed VLANs
10.0.10.0/24   → ingress tier (internet-reachable via NAT/border FW)
10.0.20-90.x   → data plane (no internet access; isolated by ACL)
10.0.100.0/24  → management (Ansible SSH, IPMI -- restricted to admin CIDR)

BGP-free internal routing: static routes only
No eBGP to sensor endpoints -- sensors push over HTTPS (no return routing needed)
```

---

## 6. Storage Architecture

### Storage Tier Hierarchy

```
Tier 0: GPU VRAM (ephemeral)    4× 80 GB VRAM       Model KV cache, activations
Tier 1: DRAM (volatile)         256–1024 GB RAM     NATS in-flight, Qdrant HNSW, DuckDB
Tier 2: NVMe (local)            8–32 TB per node    JetStream persist, DuckDB scratch
Tier 3: SAS HDD / S3 (archive)  200 TB – unlimited  Parquet cold store, model weights
```

### Parquet Data Flow and Retention

```
Sensor → Parquet (ZSTD) → NATS JetStream (Tier 2 NVMe, 24h)
                         ↓ worker_s3_archive
                    S3/MinIO Hive partition (Tier 3, 90-day hot)
                         ↓ S3 lifecycle policy
                    Glacier / S3 Deep Archive (Tier 3, 1-year forensic)
                         ↓ 01_spool_datasets.py (MLOps)
                    DuckDB local NVMe scratch (Tier 2, training window)
```

### Data Retention Policy

| Data Type | Hot (NVMe) | Warm (S3 Standard) | Cold (Glacier) | Delete |
|---|---|---|---|---|
| JetStream messages | 24h | -- | -- | 24h auto |
| Parquet telemetry | -- | 90 days | 1 year | 365 days |
| Qdrant vectors | Rolling 30 days | -- | -- | Auto evict (LRU) |
| MLOps training datasets | 180 days NVMe | -- | -- | On retraining cycle |
| Model weights | Indefinite NVMe | S3 (latest 10) | -- | Manual |
| RLHF feedback | 180 days | -- | -- | After DPO cycle |
| Audit logs (SOAR) | -- | 1 year | 7 years | Compliance-driven |

---

## 7. MLOps Hardware Requirements (End-to-End)

### Training Pipeline Hardware Requirements by Stage

```
Stage 0: Data Preparation (generate_golden_datasets.py, 01_spool_datasets.py)
  Node:     Analytics node (Node 15)
  CPU:      All 96 cores (DuckDB parallel Parquet scan)
  RAM:      256–512 GB active (scanning 30-day Parquet window)
  NVMe:     16 TB scratch for Parquet cache + JSONL staging
  Network:  100 GbE to S3 (spooling 180-day training window)
  Duration: 30–90 minutes for full spool

Stage 1: Model A -- BiLSTM-AE (train_lstm_ae.py)
  Node:     Analytics node (CPU-only)
  CPU:      32 cores (DataLoader workers + training loop)
  RAM:      64 GB (sliding windows, normalization state)
  GPU:      NONE -- intentionally CPU-only for inference portability
  Duration: 2–8 hours

Stage 2a: Model C CoT SFT (02_train_sft_cot.py)
  Node:     GPU cluster (Node 16) OR analytics node if 2× A100 40GB available
  GPU:      2× A100 80GB (or 4× A100 40GB)
  VRAM:     ~128 GB (Llama-3.1-8B in fp16 + gradient + optimizer = 8GB×3 + SFT overhead)
  RAM:      256 GB CPU RAM (DataLoader prefetch, tokenizer)
  NVMe:     2 TB (checkpoint saves every epoch -- Llama-3.1-8B = 16 GB per checkpoint)
  Duration: 8–24 hours (depending on dataset size)

Stage 2b: Model C QLoRA + Projector (02_train_qlora.py)
  Node:     GPU cluster
  GPU:      2× A100 80GB (tensor_parallel_size=2 for projector head alignment)
  VRAM:     ~48 GB (NF4 4-bit + LoRA r=16 adapters + SpatialProjector MLP heads)
  Duration: 4–12 hours

Stage 2c: Model B Network Adversarial (02_train_network.py)
  Node:     GPU cluster
  GPU:      2× A100 80GB (GPUs 0-1, tensor_parallel=2)
  VRAM:     ~96 GB (Mistral-Small-3.1-24B NF4 + LoRA + KV cache for training)
  RAM:      512 GB (Track 2 + Track 4 datasets in CPU RAM for DataLoader)
  Duration: 12–48 hours (dual-track curriculum)

Stage 2d: Model D DPO Critic (02_train_dpo_critic.py)
  Node:     GPU cluster
  GPU:      1× A100 80GB (Gemma-3-4B fits on single GPU during training)
  VRAM:     ~32 GB (DPO reference model + policy model both loaded)
  Duration: 4–12 hours

Stage 3: Evaluation
  Node:     GPU cluster (eval runs in parallel with idle GPU capacity)
  GPU:      1–2× A100 (eval is memory-bound, not compute-bound)
  Duration: 30–90 minutes per eval pass

Stage 4: Weight Merge + Deploy
  Node:     Analytics node (04_merge_weights.py is CPU + disk I/O)
  NVMe:     24 GB free per merge (full precision temporary weights)
  Duration: 15–30 minutes
```

### MLOps I/O Performance Targets

```
01_spool_datasets.py S3 pull rate:       ≥2 GB/sec (requires 100GbE to S3 or S3 VPC endpoint)
DuckDB parquet scan throughput:          ≥10 GB/sec (8× NVMe Gen4 RAID0)
DataLoader → GPU bandwidth:              ≥32 GB/sec (PCIe 4.0 × 16 host NVMe → GPU)
Checkpoint write (16 GB model):          <60 seconds (NVMe RAID0 at 10 GB/sec)
Model weight copy (analytics → GPU):     <30 seconds (100 GbE = 12.5 GB/sec)
```

### MLOps Scheduling Constraints

```
Training MUST be serialized (Models A → B → C → D):
  - Cannot train Model B and C simultaneously (GPU memory contention)
  - Model D (critic) can train on GPU 2-3 while Model B runs on GPU 0-1
  - MLOps training window: maintenance window, typically 02:00–06:00

Inference MUST continue during training:
  - Inference uses GPUs 2-3 (Model C + D) full-time
  - Training only uses GPUs 0-1 (Model B) during off-peak
  - Model C training requires offline → graceful degradation protocol

GPU memory budget during concurrent inference + training:
  GPU 0-1: Model B training (80 GB VRAM × 2 = 160 GB) → FULL
  GPU 2-3: Model C inference (80 GB) + Model D inference (16 GB) = 96 GB / 160 GB
           Remaining 64 GB: KV cache for active investigations
```

---

## 8. Operating System and Software Requirements

### Bare Metal Nodes (NATS, Qdrant, Analytics, GPU, MinIO)

```
OS:           Debian 12 "Bookworm" (server minimal, no desktop)
              Rationale: systemd, predictable LTS lifecycle, stable kernel packaging

Kernel:       6.6 LTS (linux-image-6.6-amd64 from backports)
              Required features:
                io_uring:         enabled (Rust sensors, NATS)
                kTLS:             enabled (SSL offload in Rust Axum)
                IOMMU:            enabled (GPU passthrough readiness)
                hugepages:        enabled (Qdrant MMAP, DuckDB)
                BPF/eBPF:         enabled (linux_sentinel eBPF probes)
                cgroup v2:        enabled (Podman rootless containers)

Container:    Podman 5.x (rootless, no daemon)
              Quadlet for systemd-native container management
              NO Docker daemon (security surface reduction)

Storage:      mdadm for NVMe RAID10 (NATS, Qdrant)
              LVM thin provisioning for flexible partition management
              XFS filesystem (better than ext4 for large files and parallel I/O)

Networking:   systemd-networkd (not NetworkManager)
              bonding driver: active-backup (failover) or 802.3ad (LACP throughput)
              VLAN sub-interfaces via .network and .netdev units

Security:     AppArmor (Debian default; simpler than SELinux for this stack)
              nftables (NOT iptables-legacy)
              SSH: ed25519 host keys only; no password auth; AllowUsers nexus-admin
```

### VM Nodes (Ingress, Redis, Workers, TI, Management)

```
OS:           Debian 12 (same as bare metal -- single base image)
VMware tools: open-vm-tools (NOT proprietary VMware tools)
NIC:          VMXNET3 (not E1000 -- VMXNET3 has SR-IOV capability)
Disk:         SCSI paravirtual controller (NOT IDE, not LSI)
Memory:       Do NOT use balloon driver for Redis, NATS consumers, Qdrant
              Set mem.shares = "high" in VMware for memory-critical VMs
```

### GPU Inference Node -- Additional Requirements

```
NVIDIA drivers:  535.x (or latest production branch, not beta)
                 nvidia-smi must report: Persistence Mode: On
CUDA:            12.4+ (required for FlashAttention v2, PagedAttention)
DCGM:            Data Center GPU Manager for health monitoring
nvidia-fabricmanager: REQUIRED for NVLink (without it, multi-GPU fails)
Container:       nvidia-container-toolkit 1.17+ (Podman GPU support)

BIOS requirements:
  - SR-IOV: enabled
  - PCIe Above 4G Decoding: enabled (required for multiple GPU cards)
  - Re-Size BAR: enabled (memory-mapped I/O optimization)
  - NUMA interleaving: DISABLED (let NUMA affinity work naturally)
  - C-states: disabled (consistent inference latency)
  - Turbo/Boost: ENABLED (GPU power limit set by DCGM separately)
  - Hyper-Threading: enabled (GPU inference is not HT-sensitive)
```

---

## 9. Cost Model Summary

### On-Premises (VMware + Bare Metal)

```
Hardware (one-time):
  2× Ingress (VMs):               $0 (from VMware cluster)
  3× NATS bare metal (2U):        $45,000 × 3 = $135,000
  3× Qdrant bare metal (2U):      $65,000 × 3 = $195,000
  1× Analytics bare metal (4U):   $95,000
  1× GPU inference (8× A100 SXM): $350,000–$450,000
  1× MinIO storage (4-node):      $80,000
  VMware ESXi cluster (3 hosts):  $60,000
  1× TI + Management (VMs):       $0 (from VMware cluster)
  Network fabric (spine+leaf):    $80,000
  Cabling, rack, PDU, UPS:        $40,000
  ─────────────────────────────────────────
  Total hardware:                 ~$1,035,000 – $1,135,000

Power (annual, $0.12/kWh):
  NATS (3×, 1kW each):            $3,154/yr
  Qdrant (3×, 1.2kW each):        $3,784/yr
  Analytics (2.5kW):              $2,628/yr
  GPU inference (3kW sustained):  $3,154/yr
  MinIO (2kW):                    $2,102/yr
  Misc VMs + network:             $5,000/yr
  ─────────────────────────────────────────
  Total power:                    ~$20,000/yr

Colocation (if applicable):        $8,000–$15,000/month for 20U rack space + 20kW power
```

### AWS (Cloud -- Medium Tier, On-Demand, us-east-1)

```
Monthly estimates:
  NATS (3× i4i.8xlarge):         $3,280 × 3 = $9,840
  Qdrant (3× r7iz.16xlarge):     $9,500 × 3 = $28,500
  Analytics (r7iz.metal-32xl):   $22,000
  GPU Inference (p4de.24xlarge): $40,000
  Workers (4× c7i.8xlarge):      $1,400 × 4 = $5,600
  Redis (2× r7i.4xlarge):        $1,000 × 2 = $2,000
  Ingress (2× m7i.4xlarge):      $650 × 2 = $1,300
  TI (r7i.2xlarge):              $500
  Management (t3.xlarge):        $150
  S3 storage (1,107 TB 90-day):  $25,461
  Data transfer (egress):        $5,000 (estimate)
  ─────────────────────────────────────────
  Total AWS monthly:             ~$140,351

  With 1-yr Savings Plans (40% discount on compute):
  Total AWS monthly:             ~$90,000–$100,000
```

---

## 10. Terraform Updates Required

The following changes must be made to the existing Terraform configurations to match these specs:

### VMware (`infrastructure/terraform/vmware/main.tf`)

```hcl
# NATS nodes -- increase from 8 vCPU/32 GB to production spec
resource "vsphere_virtual_machine" "nats_nodes" {
  # ⚠ NATS MUST be bare metal -- remove from VMware Terraform
  # Deploy NATS via Ansible on physical servers, not as VMs
  # See: infrastructure/ansible/roles/nats_node/tasks/main.yml
}

# Qdrant nodes -- increase from 16 vCPU/64 GB to minimum production
resource "vsphere_virtual_machine" "qdrant_nodes" {
  num_cpus = 64         # was: 16
  memory   = 524288     # 512 GB -- was: 65536 (64 GB)
  disk { label = "disk1", size = 8192 }  # 8 TB NVMe -- was: 500 GB
}

# Analytics -- increase from 16 vCPU/64 GB to production spec
resource "vsphere_virtual_machine" "analytics" {
  num_cpus = 96         # was: 16
  memory   = 786432     # 768 GB -- was: 65536 (64 GB)
  disk { label = "disk1", size = 32768 }  # 32 TB NVMe scratch -- was: 200 GB
  # ⚠ Deploy as bare metal, not VM -- see notes above
}
```

### AWS (`infrastructure/terraform/aws/main.tf`)

```hcl
# NATS -- upgrade from i4i.xlarge (4 vCPU/32 GB) to i4i.8xlarge
resource "aws_instance" "nats" {
  instance_type = "i4i.8xlarge"   # was: "i4i.xlarge"
  count         = 3
  placement_group = aws_placement_group.nexus_cluster.id
  # i4i has local NVMe -- DO NOT use EBS for JetStream
}

# Qdrant -- upgrade from r6i.2xlarge (8 vCPU/64 GB) to r7iz.16xlarge
resource "aws_instance" "qdrant" {
  instance_type = "r7iz.16xlarge"  # was: "r6i.2xlarge"
  count         = 3
  placement_group = aws_placement_group.nexus_cluster.id
  root_block_device {
    volume_type = "io2"
    volume_size = 100
    iops        = 3000
  }
  ebs_block_device {
    device_name = "/dev/sdb"
    volume_type = "io2"
    volume_size = 4000    # 4 TB per Qdrant node
    iops        = 64000
    throughput  = 4000
  }
}

# Analytics -- upgrade from r6i.2xlarge to bare metal
resource "aws_instance" "analytics" {
  instance_type = "r7iz.metal-32xl"  # was: "r6i.2xlarge"
  placement_group = aws_placement_group.nexus_cluster.id
  ebs_block_device {
    device_name = "/dev/sdb"
    volume_type = "io2"
    volume_size = 8000    # 8 TB NVMe-equivalent EBS
    iops        = 256000  # io2 Block Express max
    throughput  = 4000
  }
}

# GPU Inference -- add missing resource
resource "aws_instance" "gpu_inference" {
  instance_type          = "p4de.24xlarge"
  ami                    = data.aws_ami.nexus_gpu_base.id
  key_name               = aws_key_pair.nexus_admin.key_name
  subnet_id              = module.vpc.private_subnets[0]
  vpc_security_group_ids = [aws_security_group.internal_mesh.id]
  placement_group        = aws_placement_group.nexus_cluster.id
  ebs_optimized          = true

  root_block_device {
    volume_type = "io2"
    volume_size = 200
    iops        = 10000
  }

  tags = { Name = "nexus-gpu-inference", Role = "inference" }
}
```

---

## Appendix A: Quick Reference -- Node Summary

| Role | Count | RAM | NVMe | NIC | Bare Metal? |
|---|---|---|---|---|---|
| Ingress (HAProxy+Axum) | 2 | 32 GB | 500 GB | 2×25GbE | No |
| NATS JetStream | 3 | 256 GB | 16 TB | 2×25GbE | **Yes** |
| Redis | 2 | 128 GB | 500 GB | 10GbE | No |
| Qdrant vector DB | 3 | 512 GB | 8 TB | 2×25GbE | **Yes** |
| Rust Workers | 4 | 128 GB | 1 TB | 10GbE | No |
| Analytics/MLOps | 1 | 512–768 GB | 32 TB | 1×100GbE+1×25GbE | **Yes** |
| GPU Inference (4×A100) | 1 | 768 GB | 4 TB | 2×100GbE | **Yes** |
| MinIO Storage | 1–4 | 128–256 GB | 8 TB NVMe+200 TB HDD | 2×25GbE | **Yes** |
| TI (OpenCTI) | 1 | 64 GB | 2 TB | 10GbE | No |
| Management | 1 | 32 GB | 500 GB | 1GbE | No |

## Appendix B: Scaling Factors

To scale from Medium (50K endpoints) to Large (500K endpoints):
- NATS: 3 nodes → 9 nodes (3× throughput, same NVMe per node)
- Qdrant: 3 nodes → 9 nodes (3× vector capacity)
- Workers: 4 nodes → 16 nodes (4× Parquet throughput)
- Analytics: 1 node → 2 nodes (active/standby for MLOps)
- GPU: 1 host → 3 hosts (parallel model serving)
- MinIO: 200 TB → 2 PB (expand node count or HDD capacity)
- S3 costs scale linearly

Small (5K endpoints) can run on:
- 1 NATS node, 1 Qdrant node, 1 worker, 1 analytics (all as VMs or single bare-metal)
- GPU inference: 2× A100 40GB (g5.12xlarge on AWS)
- Total AWS cost: ~$12,000–$15,000/month

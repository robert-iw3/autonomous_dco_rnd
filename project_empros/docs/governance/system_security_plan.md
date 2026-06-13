---
title: "System Security Plan"
subtitle: "Sentinel Nexus — Autonomous Agentic SOC Platform"
author: "RW"
date: "June 2026"
version: "1.0"
---

\newpage

## Document Control

| Field | Value |
|---|---|
| Document title | System Security Plan (SSP) — Sentinel Nexus |
| Version | 1.0 |
| Date | 2026-06-12 |
| Classification | Public |
| System owner | The man, the myth, the legend |
| Authorizing official | (assign at ATO) |
| Review cadence | Quarterly, or on material architecture change |
| Frameworks | NIST SP 800-53 Rev. 5 · NIST CSF 2.0 · NIST AI 600-1 (GenAI Profile) / AI RMF 1.0 |

**Companion documents:** `security_controls.md` (control manifest),
`nist_ai_600_1_control_tracker.md` (AI control implementation status), and the
governance set in this directory (AI system inventory, GAI risk-tier statement,
incident response plan, data-retention/decommission policy, applicability
determinations, environmental-impact estimate).

\newpage

## 1. System Identification & Categorization

**System name:** Sentinel Nexus — an autonomous, air-gap-capable agentic Security
Operations Center (SOC) platform that detects, investigates, and contains threats at
machine speed across a 50,000+ endpoint estate.

**Operating model:** sovereign / on-premises or single-tenant cloud, with an
air-gapped deployment mode (`NEXUS_OFFLINE_MODE`) in which no telemetry or model
egress crosses the enclave boundary.

**Security categorization (FIPS-199 style):**

| Objective | Impact | Rationale |
|---|---|---|
| Confidentiality | **High** | Processes security telemetry, credentials in transit, and threat-intel; a breach exposes the defended estate's posture. |
| Integrity | **High** | Drives autonomous containment; tampered verdicts or models could disrupt production or suppress detection. |
| Availability | **Moderate** | Detection latency is operationally important, but the platform fails safe (degrades to monitoring) rather than mis-acting. |

**Overall categorization: HIGH.**

## 2. System Description & Architecture

A four-tier correlation engine that shifts the kill chain left:

- **Layer 1 — Vector tripwires.** Rust workers map normalized UEBA telemetry into
  Qdrant HNSW indices; cosine-similarity anomalies (zero-days, living-off-the-land)
  trigger downstream analysis.
- **Layer 2 — Deterministic engine.** A zero-copy Rust worker evaluates Sigma-style
  rules over the NATS JetStream Parquet bus.
- **Layer 3 — Agentic closer (LLM Hunter swarm).** A LangGraph DAG —
  supervisor → host/net/cloud/nettap experts → adversarial review board →
  response agent — performs bounded, read-only forensic pivots over cold storage
  (DuckDB/Parquet), Qdrant, threat intel, and the enterprise SIEMs (Splunk/Elastic),
  reaching a governed verdict that drives SOAR.
- **Sovereign Threat Intel.** Air-gapped OpenCTI 6.8 (MITRE ATT&CK pre-loaded).

**Model inventory (developer + deployer roles):** four fine-tuned models
(A: network baseline LSTM-AE; B: adversarial pattern classifier; C: spatial endpoint
expert; D: SOAR critic / blast-radius evaluator) plus optional frontier models
(Anthropic / Azure) in a sovereign-by-default failover chain. Full detail in the
AI System Inventory.

**Authorization boundary:** the Nexus enclave — ingestion gateway, NATS cluster,
Redis, Qdrant, MinIO/S3 cold storage, the Rust worker fleet, the middleware ETL
fanout, the LLM Hunter swarm, the MLOps training/serving planes, the Det Chamber
detonation sandbox, and the SOAR/operations interface. External SIEMs, frontier
model APIs, and external TI providers are **interconnections**, not in-boundary.

### 2.1 Secure Data Ingestion & Transmission Path

Telemetry enters the enclave through a **Zero-Trust ingestion gateway**
(`services/core_ingress`, an Axum service) that treats every sensor as untrusted
until cryptographically proven. The path enforces defense-in-depth *before* a single
event reaches the bus or storage (SC-7, SC-8, SC-16, SI-7, SI-10):

1. **Transport security (SC-8).** Mutual TLS termination at HAProxy to the gateway;
   JWT bearer authorization (minted per ingress node, audience-scoped) gates the API.
2. **Cryptographic lineage integrity (SI-7, SC-16).** Every Rust sensor stamps each
   Parquet batch with an HMAC-SHA256 `nexus_integrity` tag over a **canonical byte
   order** — `parquet ‖ seq_BE ‖ sensor_id ‖ ts_BE` (big-endian sequence and
   timestamp) — keyed by a Vault-provisioned `integrity_secret`. The gateway recomputes
   and verifies it; a mismatch is rejected. (A historical bug where the stamp used
   little-endian / wrong field order silently 400-banned every Rust sensor; it was
   found, fixed, and is now contract-tested.)
3. **Three-tier replay & tamper defense (SI-10, SC-5).** Beyond the HMAC the gateway
   independently validates **temporal drift** (timestamp within a bounded ±30 s window
   — rejects replayed/back-dated batches), **monotonic sequence** (per-sensor counter
   must advance — rejects replay/reorder), and **cross-OS consistency** + **collision
   detection** on the lineage tuple.
4. **Input validation (SI-10).** Sensor-controlled `endpoint_id` values are regex-
   validated (`^[a-zA-Z0-9\-]{3,64}$`) in the Rust ingestion layer before reaching
   Qdrant or Parquet — blocking injection / path-traversal via sensor fields.
5. **Adaptive sensor banning (AC-7, SI-4).** Repeated integrity failures past
   `integrity_ban_threshold` trip a **persistent** ban (survives restarts), bounding a
   compromised or spoofing sensor's blast radius.
6. **Exactly-once downstream.** Accepted events deduplicate on `event_id` (7-day Redis
   `SETNX`); SOAR actions carry a 15-minute rolling idempotency key as a `Nats-Msg-Id`
   header so containment applies exactly once.

From the gateway, validated telemetry flows over **NATS JetStream** (default-deny
subject authorization, 3-node quorum, durable consumers) to the Rust worker fleet
(`worker_qdrant` vector tripwires, `worker_rules` Sigma, `worker_s3_archive` Hive-
partitioned cold storage) and, via the **middleware ETL fanout**, to the enterprise
SIEMs — each hop carrying OTLP trace context and DLQ routing for poison messages. A
data-flow **conservation test** proves no event is silently dropped between hops.

> **Code evidence.** Each safeguard above is answered by the *actual source*, extracted
> and cited by `file:line` in the **Control Evidence Dossier** (`control_evidence.pdf`):
> HMAC lineage + constant-time compare + replay window (`artifacts/ING-ZERO-TRUST.md`),
> `endpoint_id` regex validation (`artifacts/SEC-ENDPOINT-ID.md`), the idempotency key
> (`artifacts/SEC-IDEMPOTENT-SOAR.md`), and DLQ/circuit-breaker routing
> (`artifacts/ING-DLQ-BREAKER.md`). The full per-control index is **Annex B**.

## 3. NIST SP 800-53 Rev. 5 — Control Implementation Summary

Status legend: **I** implemented · **P** partial · **PL** planned.

### 3.0 Infrastructure Hardening (Infrastructure-as-Code, Layer 0)

A large share of the technical safeguards is enforced declaratively and idempotently
by the `hardening/` and `infrastructure/ansible/roles/common_hardening` roles, applied
as the **first** play in `site.yml` (Layer 0) before any service is deployed — so no
workload ever runs on an unhardened host. The IaC encodes a CIS-style baseline:

- **Kernel & network stack (SC-7, SC-5, SI-16).** `sysctl` baseline: full ASLR
  (`kernel.randomize_va_space=2`), `kernel.dmesg_restrict`, reverse-path filtering,
  TCP SYN cookies, ignore ICMP broadcasts / bogus responses, disable source routing,
  ICMP redirect accept/secure-redirects off, martian logging, and `fs.suid_dumpable=0`
  with core dumps disabled (limits.conf + sysctl).
- **Filesystem mount hardening (CM-7, AC-6).** `/tmp` and `/dev/shm` mounted
  `noexec,nosuid,nodev`; restrictive permissions on `/etc/crontab` and the cron
  directories; default `umask 077`.
- **SSH (AC-17, IA-2, SC-8).** `Protocol 2`, `PermitRootLogin no`, no password,
  empty, or host-based auth, strong KEX / Ciphers / MACs only, `AllowGroups`
  allow-listing, bounded `MaxAuthTries` / `MaxStartups` / `LoginGraceTime`, idle
  `ClientAlive` timeout, X11 / agent / TCP forwarding disabled, `LogLevel VERBOSE`,
  and a legal login banner.
- **Host firewall (SC-7).** Default-**DROP** firewalld zone (RHEL) / UFW (Debian) with
  an explicit service/port allow-list and a trusted-subnet rule; zone-drifting disabled.
- **Brute-force & integrity (SI-3, SI-7, SI-4).** `fail2ban` on auth surfaces; **AIDE**
  file-integrity monitoring; `auditd` enabled with a rule set watching the identity
  files (`/etc/passwd|shadow|group|gshadow|sudoers`), PAM, `su`/`sudo` execution, and
  the **Podman** runtime/socket/config — giving tamper-evident audit of the container
  control plane (AU-2, AU-12).
- **Account policy (AC-2, IA-5).** Password aging (max 60 / min 1 days, history 5, max
  3 retries) via `login.defs`/PAM; root account locked.
- **Container least-functionality (CM-7, SC-39).** Rootless/daemonless Podman with
  cgroup-v2 delegation and a `registries.conf` pull allow-list (docker.io + localhost
  only); minimal package install (security packages `aide`/`fail2ban`/`auditd` added,
  unnecessary services removed).

These Layer-0 mechanisms underpin the SC, SI, AC, AU, and CM families below; the
service-tier controls in those tables build on this hardened substrate. The Ansible
task orchestration that applies them is extracted in `artifacts/IAC-HARDENING.md`
(control **IAC-HARDENING**; see Annex B).

### Access Control (AC)
| Control | Status | Implementation |
|---|---|---|
| AC-2 Account management | I | Authentik IdP (OIDC), RBAC for operator personas; per-service NATS subject-level auth. |
| AC-3 Access enforcement | I | Agent tool visibility is role-scoped (`tools/__init__.py` RBAC: per-expert kits, counterpart kit with no mutation/acquire). Read-only data-lake + SIEM sandboxes. |
| AC-4 Information flow enforcement | I | Sovereign-by-default egress: TI providers, frontier models, and SIEM backends are inert unless explicitly enabled + keyed; outbound DLP scrub. |
| AC-6 Least privilege | I | S3 creds scoped to `GetObject`; the host expert alone holds acquisition agency; counterparts cannot write entity state. |

### Audit & Accountability (AU)
| Control | Status | Implementation |
|---|---|---|
| AU-2/AU-3 Auditable events / content | I | Structured incident reports (AI-provenance stamped), SOAR audit reason (DLP-scrubbed), Prometheus metrics, RSI/calibration/bias-audit ledgers. |
| AU-6 Audit review | P | Bias-audit job (NC-1), calibration ledger (NC-2), and automation-bias/over-reliance metrics (NC-8) provide periodic review signals; SIEM forwards mirror events. |
| AU-9 Protection of audit information | I | Append-only ledgers; **tamper-evident verdict-lineage SHA-256 hash chain (NC-10)** detects post-hoc edits; DR snapshots to S3; reports tracked in version control. |
| AU-10 Non-repudiation | I | The verdict-lineage hash chain binds each autonomous decision to the prior entry's hash, giving a non-repudiable, verifiable decision trail (NC-10). |

### Configuration Management (CM)
| Control | Status | Implementation |
|---|---|---|
| CM-2 Baseline configuration | I | IaC (Ansible/Terraform), pinned container versions, `nexus.toml` single source of truth with cross-config contract tests. |
| CM-3 Change control | I | GitLab 7-stage CI/CD; deploy-blocking eval gates; per-section test harness (`run_tests.sh`). |
| CM-7 Least functionality | I | Read-only query sandboxes (DuckDB, SIEM), keyword/command allowlists, local-FS block. |

### Contingency Planning (CP)
| Control | Status | Implementation |
|---|---|---|
| CP-9 System backup | I | Nightly Qdrant + Redis → S3 DR snapshots (7-day retention); Terraform remote state. |
| CP-10 Recovery | I | Durable worker circuit breaker + DLQ; supervised tokio restart; model registry re-pin rollback (planned, WS-A). |

### Identification & Authentication (IA)
| Control | Status | Implementation |
|---|---|---|
| IA-2/IA-5 Authentication / authenticators | I | OIDC for operators; NATS user/pass per role; HMAC-SHA256 sensor integrity stamping; Vault-backed runtime secrets. |

### Incident Response (IR)
| Control | Status | Implementation |
|---|---|---|
| IR-4 Incident handling | I | The platform *is* the incident-handling engine (detect → investigate → contain via SOAR) with HitL circuit breaker; cognitive-fault DLQ. |
| IR-5/IR-6 Monitoring / reporting | P | AI Incident Response Plan (this directory) defines AI-incident criteria + after-action template; formal external reporting pathway PL. |

### Risk Assessment (RA)
| Control | Status | Implementation |
|---|---|---|
| RA-3 Risk assessment | I | NIST AI 600-1 gap analysis + control tracker; GAI risk-tier statement. |
| RA-5 Vulnerability monitoring | I | Red-team CI gate (cognitive bypass), AI red-teaming (garak/PyRIT scaffolds), dependency pinning (RUSTSEC), anchore scans in deployment-prep. |

### System & Communications Protection (SC)
| Control | Status | Implementation |
|---|---|---|
| SC-7 Boundary protection | I | Zero-Trust Axum gateway (TLS, JWT, 3-tier integrity), HAProxy mTLS, default-deny NATS authz, k8s NetworkPolicy, isolated detonation network. |
| SC-8 Transmission confidentiality/integrity | I | TLS throughout; HMAC lineage stamping; canonical field-order integrity. |
| SC-28 Protection at rest | I | Parquet cold storage on access-controlled MinIO/S3; SQLite buffers gitignored; secrets in Vault/Ansible-Vault. |

### System & Information Integrity (SI)
| Control | Status | Implementation |
|---|---|---|
| SI-3 Malicious code protection | I | Det Chamber isolated detonation; cross-OS schema-injection corpus; sensor input regex validation. |
| SI-4 System monitoring | I | The detection mission itself; canary leak tripwire halts SOAR; conservation-tested data flow. |
| SI-7 Software/firmware/information integrity | I | SHA-384 model-weight verification at boot; SoarExecutionSchema output contract; review-board grounding control (cited evidence must resolve); tamper-evident verdict-lineage hash chain (NC-10). |
| SI-10 Information input validation | I | Cognitive sanitizer (`<untrusted_payload>` wrapping, control-token defang, boundary isolation) on all adversary-controlled telemetry and SIEM results. |

### Supply Chain Risk Management (SR)
| Control | Status | Implementation |
|---|---|---|
| SR-3/SR-4 Supply chain controls / provenance | I | SHA-384 weight manifests; pinned base images; air-gap bundle with SBOM/scan; frontier-model version-pin enforcement (NC-3). |
| SR-11 Component authenticity | I | Cryptographic model supply-chain integrity (ATLAS AML.T0044). |

## 4. NIST CSF 2.0 — Function Implementation

| Function | Coverage |
|---|---|
| **GOVERN (GV)** | AI governance via the NIST AI 600-1 control tracker + this SSP; GAI risk-tier statement; sovereign-by-default policy; roles & RBAC; supply-chain governance. |
| **IDENTIFY (ID)** | AI system inventory; asset criticality registry (TIER-1 assets force HitL); risk assessment (gap analysis); applicability determinations. |
| **PROTECT (PR)** | Zero-Trust gateway, RBAC, read-only sandboxes, DLP egress, encryption, secrets management, prompt-injection defenses, model-integrity verification. |
| **DETECT (DE)** | The core mission: 3-layer correlation (vector/rule/agentic), canary tripwires, conservation tracking, continuous monitoring. |
| **RESPOND (RS)** | Governed SOAR with HitL circuit breaker; cognitive-fault DLQ; AI incident response plan; review-board fail-closed verdicts. |
| **RECOVER (RC)** | DR snapshots; durable-worker recovery; FP-restore playbooks; planned model-registry re-pin rollback. |

## 5. AI-Specific Controls (NIST AI 600-1 / AI RMF)

The platform is both a GAI **developer** (fine-tunes Models A–D) and **deployer**
(runs frontier + local inference). Implementation status is maintained in
`nist_ai_600_1_control_tracker.md`; highlights:

- **Confabulation (2.2):** review-board evidence-grounding (cited artifacts must
  resolve to retrieved evidence); deterministic regression gate; confidence
  calibration ledger (NC-2); **active-learning failure capture** — misclassified
  or ungrounded verdicts are written to a hard-example corpus for continuous
  improvement (NC-9).
- **Information Security (2.9):** the platform's strongest area — canary,
  boundary isolation, read-only sandboxes, supply-chain hashing, DLQ.
- **Information Integrity (2.8):** AI-provenance-stamped reports; append-only audit
  ledgers; **tamper-evident verdict lineage** — a SHA-256 hash chain over verdict
  records so any post-hoc edit, deletion, or reorder is detectable (NC-10).
- **Harmful Bias & Homogenization (2.6):** disaggregated fairness audit + immunity-
  memory homogenization monitor, run as a scheduled control (NC-1).
- **Human-AI Configuration (2.7):** HitL circuit breaker, AI-origin disclosure on
  reports, TIER-1 manual review, and **automation-bias / over-reliance measurement**
  — accept-vs-override outcomes are tracked so rubber-stamping of wrong AI calls is
  quantified, not assumed away (NC-8).
- **Environmental Impacts (2.5):** one-time footprint estimate (NC-6) plus **per-run
  energy/carbon accounting in code** feeding the MLOps metric plane (NC-11).
- **Value Chain (2.12):** frontier-model version-pin enforcement (NC-3),
  supply-chain integrity, weight manifests.

The misuse / content-generation risk families (CBRN, CSAM/NCII, dangerous/obscene
content, IP infringement) are determined **not applicable** — the platform consumes
adversary telemetry and emits internal SOC verdicts; it is not a public content
generator. See the Applicability Determinations document.

## 6. Plan of Action & Milestones (POA&M)

| ID | Item | Control | Target |
|---|---|---|---|
| POAM-1 | Schedule + alert the bias/homogenization audit, calibration ledger, and over-reliance (automation-bias) jobs on a cron/RSI cadence | AU-6, RA-3 | next sprint |
| POAM-2 | Formalize external AI-incident reporting pathway | IR-6 | next sprint |
| POAM-3 | Model registry + steward (pull-based promotion, re-pin rollback) | CM-3, CP-10 | WS-A B2.5 |
| POAM-4 | RAG-memory retention enforcement + membership-inference review | SC-28, AU-9 | per retention policy |
| POAM-5 | Live integration tests in CI (gateway+NATS+Qdrant) | CA-2 | hardware-gated |

## 7. Roles & Responsibilities

| Role | Responsibility |
|---|---|
| System owner | Accepts residual risk; approves the SSP and ATO. |
| AI governance lead | Maintains the AI control tracker, risk-tier statement, applicability determinations. |
| Platform engineering | Implements + tests controls; runs the deploy gates. |
| SOC operators | Disposition verdicts (feeding calibration), action HitL escalations. |
| Authorizing official | Grants/maintains the authorization to operate. |

\newpage

## Appendix A — Control Cross-Reference

This SSP summarizes; the authoritative, test-linked control detail lives in
`security_controls.md` (manifest) and `nist_ai_600_1_control_tracker.md` (AI controls,
with per-control proving tests). Every implementation claim in §3–§5 is backed by an
automated test in the `tests/` harness and reported under `tests/reports/`.

\newpage

## Annex B — Control Evidence Index

Every implemented control is answered by the **actual source code** that satisfies it,
extracted verbatim and cited by `file:line`. The per-control snippets are under
`artifacts/<CONTROL-ID>.md`; the consolidated, page-paginated set is the **Control
Evidence Dossier** (`control_evidence.pdf`). This index is **generated** from
`evidence_map.yaml` against the live tree by `gen_evidence.py` — if a cited symbol
moves, CI (`test_governance_manifest.py::TestControlEvidence`) fails until it is
regenerated, so the SSP can never cite code that no longer exists.

<!-- BEGIN EVIDENCE INDEX (generated by gen_evidence.py — do not edit by hand) -->

- **AI-GROUNDING** — Confabulated-evidence grounding. *Evidence:* artifacts/AI-GROUNDING.md — controls.py L84-L114
- **AI-MEMORY-TTL** — Immunity-memory TTL / expiry. *Evidence:* artifacts/AI-MEMORY-TTL.md — controls.py L147-L175
- **AI-PROVENANCE** — AI-origin provenance disclosure. *Evidence:* artifacts/AI-PROVENANCE.md — controls.py L178-L192
- **AI-REVIEW-BOARD** — Adversarial review board (per-expert counterparts). *Evidence:* artifacts/AI-REVIEW-BOARD.md — review_board.py L189-L217
- **IAC-HARDENING** — OS / kernel / network hardening baseline. *Evidence:* artifacts/IAC-HARDENING.md — main.yml L20-L22,L30-L32,L34-L35
- **ING-DLQ-BREAKER** — Durable worker circuit breaker + dead-letter routing. *Evidence:* artifacts/ING-DLQ-BREAKER.md — lib.rs L44-L60,L104-L110
- **ING-ZERO-TRUST** — Zero-Trust ingestion gateway (HMAC + 3-tier replay defense). *Evidence:* artifacts/ING-ZERO-TRUST.md — integrity.rs L29-L41,L46-L56,L127-L145
- **NC-1-BIAS-AUDIT** — Bias/disparity + homogenization scheduled audit. *Evidence:* artifacts/NC-1-BIAS-AUDIT.md — bias_audit.py L41-L63
- **NC-10-VERDICT-LINEAGE** — Tamper-evident verdict lineage. *Evidence:* artifacts/NC-10-VERDICT-LINEAGE.md — controls.py L486-L496; verdict_ledger.py L37-L46
- **NC-11-ENERGY-ACCOUNTING** — Per-run inference energy accounting. *Evidence:* artifacts/NC-11-ENERGY-ACCOUNTING.md — controls.py L506-L517; energy_accounting.py L23-L33
- **NC-2-CALIBRATION** — Confidence-calibration ledger. *Evidence:* artifacts/NC-2-CALIBRATION.md — calibration_ledger.py L27-L39,L81-L103
- **NC-3-FRONTIER-PIN** — Frontier model boot-time version-pin enforcement. *Evidence:* artifacts/NC-3-FRONTIER-PIN.md — llm_providers.py L148-L161
- **NC-8-OVER-RELIANCE** — Automation-bias / over-reliance measurement. *Evidence:* artifacts/NC-8-OVER-RELIANCE.md — controls.py L370-L392; calibration_ledger.py L46-L56
- **NC-9-ACTIVE-LEARNING** — Active-learning failure capture. *Evidence:* artifacts/NC-9-ACTIVE-LEARNING.md — controls.py L429-L438; active_learning.py L23-L35
- **SEC-BLAST-RADIUS** — Blast-radius cap & entity state machine. *Evidence:* artifacts/SEC-BLAST-RADIUS.md — state.py L181-L211
- **SEC-CANARY** — Canary token prompt-leak tripwire. *Evidence:* artifacts/SEC-CANARY.md — sanitizer.py L49-L58; orchestrator.py L197-L197,L258-L261
- **SEC-DLP-EGRESS** — Outbound DLP / sovereign data isolation. *Evidence:* artifacts/SEC-DLP-EGRESS.md — sanitizer.py L59-L73
- **SEC-DUCKDB-SANDBOX** — Read-only data-lake query sandbox. *Evidence:* artifacts/SEC-DUCKDB-SANDBOX.md — duckdb_query.py L78-L104
- **SEC-ENDPOINT-ID** — Endpoint identity injection defense. *Evidence:* artifacts/SEC-ENDPOINT-ID.md — models.rs L14-L20
- **SEC-FAILOVER** — Cascading LLM failover & sovereign degradation. *Evidence:* artifacts/SEC-FAILOVER.md — llm_providers.py L163-L188
- **SEC-IDEMPOTENT-SOAR** — Idempotent SOAR execution & deduplication. *Evidence:* artifacts/SEC-IDEMPOTENT-SOAR.md — response.py L252-L255
- **SEC-MODEL-DOS** — Model denial-of-service bounding. *Evidence:* artifacts/SEC-MODEL-DOS.md — orchestrator.py L55-L55,L66-L66,L186-L187
- **SEC-OUTPUT-SCHEMA** — Strict SOAR output-contract enforcement. *Evidence:* artifacts/SEC-OUTPUT-SCHEMA.md — state.py L94-L129
- **SEC-REGRESSION-GATE** — Deterministic regression / deploy gate. *Evidence:* artifacts/SEC-REGRESSION-GATE.md — 03_eval_model.py L312-L338
- **SEC-RLHF-QUARANTINE** — Sybil RLHF poisoning quarantine. *Evidence:* artifacts/SEC-RLHF-QUARANTINE.md — main.rs L132-L158
- **SEC-SANITIZER** — Cognitive boundary isolation & untrusted-payload wrapping. *Evidence:* artifacts/SEC-SANITIZER.md — sanitizer.py L24-L48,L88-L96
- **SEC-SUPPLY-CHAIN** — Cryptographic model supply-chain integrity (SHA-384). *Evidence:* artifacts/SEC-SUPPLY-CHAIN.md — serve_vllm.sh L48-L66
- **SEC-TRAINING-HYGIENE** — Training-data hygiene & credential scrubbing. *Evidence:* artifacts/SEC-TRAINING-HYGIENE.md — 01_spool_datasets.py L47-L58
- **SEC-VECTOR-DIM** — Vector dimensionality validation. *Evidence:* artifacts/SEC-VECTOR-DIM.md — qdrant_search.py L58-L72
- **SIEM-CONFIG-CONTRACT** — SIEM config ↔ fanout index contract. *Evidence:* artifacts/SIEM-CONFIG-CONTRACT.md — nexus_config.py L118-L148
- **SIEM-COUNTERPART-DISPROOF** — Review-board counterpart SIEM disproof. *Evidence:* artifacts/SIEM-COUNTERPART-DISPROOF.md — review_board.py L117-L127,L128-L156
- **SIEM-E2E** — SIEM federation end-to-end conservation. *Evidence:* artifacts/SIEM-E2E.md — test_siem_federation_e2e.py L189-L195,L222-L227
- **SIEM-TOOL-GUARD** — SIEM query tool — read-only / bounded / allowlist. *Evidence:* artifacts/SIEM-TOOL-GUARD.md — siem_query.py L110-L128,L142-L154,L155-L173

<!-- END EVIDENCE INDEX -->

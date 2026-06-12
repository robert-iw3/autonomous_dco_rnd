---
title: "AI System Inventory"
subtitle: "Sentinel Nexus — Generative & Predictive AI Components"
author: "RW"
date: "June 2026"
version: "1.0"
---

\newpage

## Purpose

Per NIST AI 600-1 **GV-1.6** (AI system inventory) and **GV-1.6-003** (inventory
entry contents), this document enumerates every AI/ML component operating within the
Sentinel Nexus authorization boundary, with the governance metadata required to manage
each across its lifecycle. It is reviewed quarterly and on any model promotion.

## Inventory entries

For each component: identifier, role, base model + provenance, artifact type, quant,
access mode, integrity control, and known issues / oversight.

### Model A — Network Baseline Engine (Math Tripwire)

| Field | Value |
|---|---|
| Role | Unsupervised network-flow anomaly pre-filter (Layer 1) |
| Architecture | Bidirectional LSTM Autoencoder (~1 MB), CPU inference |
| Data | 8-D normalized flow feature vectors (`network_tap` SPI) |
| Artifact / integrity | safetensors weights + per-feature normalization + **SHA-384 manifest** |
| Access mode | Internal NATS consumer (`nexus.alerts.baseline`); no external exposure |
| Oversight | Deterministic μ+3σ threshold; deploy-gated by `train_lstm_ae` calibration |

### Model B — Adversarial Pattern Classifier

| Field | Value |
|---|---|
| Role | Network/C2 adversarial reasoning (Tracks 2 & 4) |
| Base model | Mistral-Small-3.1-24B (pinned hf id + revision in `model_config.toml`) |
| Artifact | QLoRA 4-bit adapter / merged weights; DeepSpeed ZeRO-3 trained |
| Access mode | Internal vLLM (port 8001) |
| Oversight | `03_eval_network.py` gates (Track 2 ≥98%, Track 4 ≥95%) |

### Model C — Spatial Endpoint Expert

| Field | Value |
|---|---|
| Role | Endpoint forensic reasoning with multi-head SpatialProjector |
| Base model | pinned (`model_config.toml`); QLoRA SFT + CoT |
| Artifact | LoRA adapter + `spatial_projector.safetensors`; **SHA-384** verified at boot |
| Access mode | Internal HF Transformers inference (port 8000) |
| Oversight | `03_eval_model.py` regression gauntlet (OS-context, schema, injection, spatial boundary, cross-space, **SIEM-pivot validity**); 99% deploy floor |

### Model D — SOAR Critic / Blast-Radius Evaluator

| Field | Value |
|---|---|
| Role | Final autonomous decision gate before containment (DisruptionIndex) |
| Base model | pinned; DPO/IPO alignment |
| Artifact | LoRA adapter; **fails CLOSED** (server unreachable → `manual_review_required`) |
| Access mode | Internal vLLM (port 8002), 3-token decision space |
| Oversight | `03_eval_critic.py` 4-phase eval (DPO + governance + P/R/F1 + k-fold) |

### Agentic LLM Hunter Swarm (Model-orchestrating system)

| Field | Value |
|---|---|
| Role | Layer-3 LangGraph DAG: supervisor + 4 experts + adversarial review board + response |
| Models used | Sovereign failover chain (internal vLLM/Ollama → optional frontier) |
| Controls | Canary leak tripwire, cognitive sanitizer, read-only tool sandboxes, RBAC tool kits, review-board grounding, HitL circuit breaker, RAG-memory immunity with TTL |
| Access mode | NATS-triggered; governed SOAR dispatch only — never touches live endpoints except via SOAR / Det Chamber |

### Frontier models (optional, deployer role)

| Field | Value |
|---|---|
| Providers | Anthropic (primary), Azure OpenAI (corporate) — **sovereign-by-default, off unless enabled + keyed** |
| Version pinning | **Enforced** — boot refuses a floating alias (`*-latest`) unless `NEXUS_ALLOW_FLOATING_FRONTIER=1` (NIST MP-4.1-007, control NC-3) |
| Data egress | Cognitive sanitizer DLP scrub on outbound; internal context must not egress (air-gap posture) |
| Oversight | Provider model cards + SLAs to be captured (POA&M) |

## Required inventory metadata (GV-1.6-003) — coverage

| Item | Where maintained |
|---|---|
| Data provenance (source, versioning, integrity) | `model_config.toml`, SHA-384 manifests, corpus manifests |
| Known issues / incident links | `nist_ai_600_1_control_tracker.md` findings; AI incident plan |
| Human oversight roles | System Security Plan §7 |
| IP / licensed / sensitive-data considerations | Applicability Determinations; training-data curation policy |
| Underlying foundation models + versions + access modes | This inventory (above) |

## Supporting / non-generative ML

TurboVec n-gram dedup + hard-negative miner (corpus hygiene), IsolationForest UEBA in
the Rust/Python sensor engines, and the Qdrant HNSW vector tripwires — predictive/ML
components inside the boundary, governed by the same supply-chain and test controls.

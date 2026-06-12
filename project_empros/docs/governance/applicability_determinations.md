---
title: "NIST AI 600-1 Applicability Determinations"
subtitle: "Sentinel Nexus — Non-Applicable GAI Risk Families"
author: "RW"
date: "June 2026"
version: "1.0"
---

\newpage

## Purpose

NIST AI 600-1 expects an organization to **record the determination** even when a GAI
risk is judged out of scope (GV-1.3-003 calls for a written test/response policy). This
document states, per risk family, why several of the profile's *misuse / content-
generation* risks are **not applicable** to Sentinel Nexus, so an auditor sees a
reasoned decision rather than an omission.

## Profile-role basis

Sentinel Nexus is a defensive SOC platform: it **consumes adversary telemetry and emits
internal SOC verdicts and SOAR actions**. It is *not* a public-facing content generator
— it does not produce text, images, audio, or video for human consumption or
distribution. This posture is the common basis for the determinations below.

## Determinations

| NIST §2 risk | Determination | Rationale |
|---|---|---|
| **2.1 CBRN Information or Capabilities** | **Not applicable** | The system does not answer open-domain user questions and is not a chemical/biological design tool. Models are fine-tuned for SOC reasoning over fixed telemetry schemas; they do not synthesize CBRN knowledge. No general-purpose chat surface is exposed to users. |
| **2.3 Dangerous, Violent, or Hateful Content** | **Not applicable** | No content-generation surface. Outputs are structured verdicts (`contain`/`monitor`/`dismiss`) and forensic incident reports for internal responders, constrained by `VerdictSchema`/`SoarExecutionSchema`. |
| **2.11 Obscene, Degrading, or Abusive Content (CSAM/NCII)** | **Not applicable** | No image/audio/video generation; no public content output. Training corpora are synthetic SOC tradecraft + sanitized telemetry, curated and credential-scrubbed; no possibility of CSAM/NCII generation. |
| **2.10 Intellectual Property** | **Largely not applicable** | The system does not reproduce or generate copyrighted creative works. Residual consideration: frontier-model API terms and training-data provenance — addressed by the data-curation policy and the AI System Inventory. |
| **2.8 Information Integrity (content provenance / synthetic media)** | **Partially applicable / mostly N-A** | The profile's content-provenance / deepfake-detection concerns target public synthetic media, which Nexus does not produce. The applicable slice — provenance/traceability of the swarm's *own* reasoning — is covered by AI-origin-stamped incident reports and the audit ledgers. |

## Re-evaluation triggers

These determinations are **re-opened** if the platform's scope changes such that any of
the following becomes true (MP-4.1-008 — re-evaluate on new-domain use):

- A general-purpose, user-facing generative/chat surface is exposed.
- The system begins producing content for human consumption or external distribution.
- Models are adapted to a new domain outside SOC telemetry reasoning.
- Multimodal (image/audio/video) generation is introduced.

Until such a trigger occurs, organizational risk-management effort is concentrated on
the **applicable** high-exposure families — Confabulation, Information Security, Data
Privacy, Harmful Bias & Homogenization, Human-AI Configuration, and Value Chain — per
the NIST AI 600-1 control tracker.

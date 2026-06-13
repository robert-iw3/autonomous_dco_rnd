---
title: "Generative AI Risk-Tier Statement"
subtitle: "Sentinel Nexus -- Risk Assessment GAI"
author: "RW"
date: "June 2026"
version: "1.0"
---

\newpage

## Purpose & scope

Per NIST AI 600-1 **GV-1.3** (risk-tiering) and **GV-1.3-001** (risk-tier factors),
this statement records the risk tier assigned to the Sentinel Nexus GAI system and the
factors that justify it. It governs the level of oversight, testing robustness, and
go/no-go rigor applied to model changes.

## Risk tier: **HIGH (Tier 1 — Autonomous, consequential)**

Sentinel Nexus is assigned the organization's **highest** GAI risk tier because the
system takes **autonomous, consequential action** (network/host containment) on a
production estate at machine speed.

### Tiering factors (GV-1.3-001)

| Factor | Assessment |
|---|---|
| Autonomy / consequence | **High** — autonomous containment can isolate hosts / block traffic; a wrong action is operationally disruptive. Mitigated by HitL circuit breaker, fail-closed critic, TIER-1 manual review — with **automation-bias / over-reliance measured** (NC-8) so the human check is verified, not assumed. |
| Impact to fundamental rights / public safety | **Low–moderate** — internal defensive system; no decisions about individuals' rights. Bias risk is *allocative* (which assets get contained), monitored by the fairness audit (NC-1). |
| Information-integrity abuse potential | **Moderate** — confabulated evidence could mislead responders; mitigated by review-board grounding + deterministic eval gate + a **tamper-evident verdict-lineage hash chain** (NC-10). |
| Malicious-use / dual-use | **Moderate** — a defensive tool with read-only sandboxes; the Det Chamber detonates malware in isolation. Strong supply-chain + injection defenses. |
| New security vulnerabilities introduced | **Moderate** — LLM attack surface (prompt injection, model theft); addressed by canary, sanitizer, SHA-384 weights, red-team gates. |
| Reliability / variability over time | **Moderate** — model/data drift and the immunity feedback loop; addressed by regression gate, calibration ledger, bias/homogenization audit, model-collapse monitor. |

## Required controls at this tier

Because the system is Tier 1, the following are **mandatory** (and implemented):

- Deploy-blocking regression + alignment gates before any production weight swap
  (`03_eval_*`, red-team CI, ≥99% floor).
- Independent adversarial review (the review board) before any autonomous containment.
- Human-in-the-loop circuit breaker (DisruptionIndex, critical-asset, fleet-%).
- Fail-safe defaults everywhere (degrade to monitoring, never auto-act on missing
  signal or unreviewable verdict).
- Sovereign-by-default external dependencies (frontier models / TI / SIEM off unless
  explicitly enabled), with frontier version-pin enforcement.
- Continuous bias/homogenization auditing, confidence-calibration tracking, and
  automation-bias / over-reliance measurement of operator decisions (NC-8).
- Tamper-evident verdict lineage (NC-10) over every autonomous decision.

## Specialized risk levels (GV-1.3-005)

Two GAI-specific risk levels are tracked above the baseline:

- **Algorithmic monoculture / model collapse** — the immunity memory feeds the swarm's
  own verdicts back into analysis. Monitored by the homogenization control and bounded
  by a memory TTL; a model trained over-much on synthetic data is gated by the eval
  suite's synthetic-ratio checks.
- **Autonomous-action escalation** — any expansion of the SOAR action set or the
  acquisition/detonation capability re-enters this risk-tier review.

## Review

This tier is reviewed quarterly and on any change that alters autonomy, the action
set, the model supply chain, or the external interconnection set.

# NIST AI 600-1 (Generative AI Profile) - Control Tracker

**Subject system:** Sentinel Nexus - autonomous agentic SOC platform (LLM Hunter swarm + MLOps fine-tuning pipeline + Rust ingestion/SOAR fabric).

**Reference:** NIST AI 600-1, *AI RMF: Generative Artificial Intelligence Profile* (July 2024).

**Scope:** the 12 GAI risks in §2 and the GOVERN/MAP/MEASURE/MANAGE suggested actions in §3, tracked against the controls in [security_controls.md](security_controls.md).

**Tracked in:** [planning_docs/BACKLOG.md](../planning_docs/BACKLOG.md) → workstream **WS-B** (open items NC-1…NC-6). This document is the authoritative status for control implementation; the backlog carries the forward pointers.

**Profile role:** Sentinel Nexus is simultaneously a GAI **developer** (fine-tunes Models A-D) and a GAI **deployer** (runs frontier models via API + local inference). It is **not** a public-facing content generator - it consumes adversary telemetry and emits internal SOC verdicts/SOAR actions. That posture makes the *misuse/content-generation* risk families (CBRN, CSAM/NCII, dangerous/obscene content, IP infringement) largely non-applicable, and concentrates real exposure in **Confabulation, Information Security, Data Privacy, Harmful Bias/Homogenization, Human-AI Configuration, and Value Chain**.

---

## 0. Remediation tracker (live status)

Engineering fixes from the gap analysis (§3), with their implementing module and proving tests. All `agents/controls.py` logic is pure/stdlib-only and unit-tested in [tests/lab_analytics_hunter/test_ai_controls.py](../tests/lab_analytics_hunter/test_ai_controls.py); node wiring is proven by the integration tests noted.

| Item | NIST action | Status | Implementation | Tests |
|---|---|---|---|---|
| **P3** Confabulated-evidence grounding | MS-2.5-003 | ✅ Implemented & tested | `controls.enforce_grounding` wired into `review_board_node` | `test_ai_controls.py::TestGroundingEnforcement` + `test_review_board.py::test_workflow_confabulated_tp_is_grounding_demoted` / `..._grounded_tp_survives...` |
| **P1** Immunity-memory TTL / expiry | GV-1.3-005 | ✅ Implemented & tested | `controls.memory_is_actionable` (recall, `supervisor.py`) + `created_at` stamp (`response._persist_memory`) | `test_ai_controls.py::TestMemoryTTL` + `test_agentic_swarm_contracts.py::test_immunity_memory_has_ttl_expiry` |
| **P5** AI-origin provenance disclosure | MP-5.1-003 | ✅ Implemented & tested | `controls.stamp_ai_provenance` wired into `response_agent` | `test_ai_controls.py::TestProvenanceDisclosure` |

### Wave 2 — NC items (NC-1…NC-6)

| Item | NIST action | Status | Implementation | Tests |
|---|---|---|---|---|
| **NC-1** Bias/disparity + homogenization **scheduled audit** | MS-2.11-002, GV-1.3-005, MS-2.11-005 | ✅ Implemented & tested | `agents/bias_audit.py` (`run_bias_audit`, `collect_and_audit` w/ Qdrant scroll + report writer) over `controls.fairness_report` / `memory_homogenization` | `test_nist_controls_wave2.py::TestBiasAudit` (+ `test_ai_controls.py` pure analytics) |
| **NC-2** Calibration operator-disposition feed + Brier trend | MS-2.13-001 | ✅ Implemented & tested | `agents/calibration_ledger.py` (`record_disposition`, `brier_trend`) over `controls.calibration_record` | `test_nist_controls_wave2.py::TestCalibrationLedger` |
| **NC-3** Frontier model **boot-time pin enforcement** | MP-4.1-007 | ✅ Implemented & tested | `llm_providers.frontier_pin_allowed` gates `build_failover_chain` (refuses floating alias unless `NEXUS_ALLOW_FLOATING_FRONTIER=1`) | `test_nist_controls_wave2.py::TestFrontierPinEnforcement` + `test_ai_controls.py::TestFrontierPinning` |
| **NC-4** RAG-memory retention / decommission policy | GV-1.7-002, MS-2.10-001 | ✅ Documented (+ TTL enforced in code) | [governance/data_retention_decommission_policy.md](governance/data_retention_decommission_policy.md) | membership-inference review = POA&M-4 |
| **NC-5** Governance docs (inventory / risk-tier / incident / applicability) + **SSP** | GV-1.6, GV-1.3, MG-4.3, GV-1.3-003 | ✅ Documented (PDF) | [governance/](governance/) — system_security_plan, ai_system_inventory, gai_risk_tier_statement, ai_incident_response_plan, applicability_determinations | — |
| **NC-6** Training/inference energy estimate | MS-2.12-003 | ✅ Documented | [governance/environmental_impact_estimate.md](governance/environmental_impact_estimate.md) | — |

Legend: ✅ done · 🟨 partial (pure logic landed, integration/ops wiring remains) · ⬜ not started.

**Remaining (operational, not code):** schedule the NC-1 bias-audit + NC-2 calibration jobs on a
cron/RSI cadence and alert on a flag (POA&M-1); capture frontier model cards + SLAs; periodic
membership-inference review (POA&M-4). The control *logic and jobs* are implemented and tested.

Regression: the hunter/swarm/worker suites + the new control + wave-2 suites run green together
(SIEM-plan sweep `435 passed`; wave-2 controls `40 passed`).

---

## 1. Coverage summary

| # | GAI Risk (NIST §2) | Applicability | Coverage | Headline gap |
|---|---|---|---|---|
| 2.1 | CBRN Information or Capabilities | Low / N-A | n/a | Determination **documented** ([applicability_determinations](governance/applicability_determinations.md)) |
| 2.2 | **Confabulation** | High | 🟡 Partial | Evidence-grounding + calibration ledger (NC-2) landed; construct-validity metric & active-learning failure capture pending |
| 2.3 | Dangerous, Violent, Hateful Content | Low / N-A | n/a | Determination documented |
| 2.4 | **Data Privacy** | High | 🟡 Partial | Retention/decommission **policy landed** (NC-4) + memory TTL; periodic membership-inference review (POA&M-4) pending |
| 2.5 | Environmental Impacts | Medium | 🟡 Partial | Footprint **estimate documented** (NC-6); per-run measurement folded into the MLOps metric plane |
| 2.6 | **Harmful Bias & Homogenization** | High | 🟢 Strong | Disparity + homogenization run as a **scheduled audit job** (NC-1, `bias_audit`) over the tested analytics + memory TTL; cron alerting (POA&M-1) + model-card bias eval remain |
| 2.7 | **Human-AI Configuration** | High | 🟡 Partial | AI-origin disclosure + **calibration feed/Brier ledger** (NC-2) + HitL landed; automation-bias / over-reliance measurement pending |
| 2.8 | Information Integrity | Medium | 🟡 Partial | Provenance-stamped reports + audit ledgers; tamper-evident verdict-lineage chain remains |
| 2.9 | **Information Security** | High | 🟢 Strong | Strongest area; AI-incident process now **documented** (governance/), periodic red-team cadence remains |
| 2.10 | Intellectual Property | Low / N-A | n/a | Determination documented; frontier data/IP terms = inventory POA&M |
| 2.11 | Obscene / CSAM / NCII | N-A | n/a | Determination documented |
| 2.12 | **Value Chain & Component Integration** | High | 🟡 Partial | **Frontier boot-time pin enforcement** landed (NC-3); model-card review, version-drift re-eval, SBOM & vendor SLA pending |

**Cross-cutting GOVERN — now closed (documented in [governance/](governance/)):** AI system inventory
(GV-1.6), GAI risk-tiering (GV-1.3), AI incident-response + after-action template (GV-4.3 / MG-4.3),
decommissioning protocol (GV-1.7), applicability determinations (GV-1.3-003), and the **System
Security Plan** (SP 800-53 + CSF 2.0 + AI RMF). Remaining items are operational (scheduling, model
cards, periodic reviews), tracked in the SSP POA&M.

Legend: 🟢 Strong · 🟡 Partial · 🔴 Gap.

---

## 2. What the existing controls already satisfy

The current manifest maps cleanly onto the **Information Security** and **prompt-injection/output-handling** portions of the profile - the system's core competency.

| Existing control | NIST AI 600-1 actions satisfied |
|---|---|
| Canary Token Verification | MS-2.6-006, MS-2.7-007 (GAI attacks - prompt injection), MS-4.2-001 |
| Cognitive Boundary Isolation (`CognitiveSanitizer` + `<untrusted_payload>`) | MS-2.7-007, MS-2.6-006; Information Integrity (untrusted content ≠ instructions) |
| Strict Output Enforcement (`SoarExecutionSchema`) | GV-1.3-002, MS-2.6-004 (review outputs/code for unreliable downstream decisions), excessive-agency control |
| Read-Only Data Lake Sandboxing (DuckDB blocklist + LIMIT cap) | MS-2.6-006, Information Security; bounded autonomy |
| Cryptographic Model Supply-Chain Integrity (SHA-384 weight verify) | MS-2.7-001 (model theft/weight exposure), MS-2.7-005 (model-integrity verification), MG-3.1-005 |
| Sybil RLHF Poisoning Quarantine | MS-2.7-007 (data poisoning / membership), MG-3.1-002 (value-chain data poisoning) |
| DLP `CognitiveSanitizer` (RFC-1918 + credential scrub before frontier egress) | MP-4.1-009 (detect PII in output), MS-2.2-002 (privacy output filters), GV-1.2-001 |
| Training Data Hygiene & Credential Scrubbing (`01_spool_chatml.py`) | MP-4.1-004 (data-curation policy), MS-2.6-002 (assess PII in training data) |
| Deterministic Regression Gate (`03_eval_model.py`, 99% floor) | GV-1.3-002 (go/no-go thresholds), MS-2.3-002 (validated capability claims), Confabulation (OS-context hallucination axis) |
| Adversarial Review Board (`review_board_node`) | MG-1.3-002 (monitor robustness via skeptical second pass), Overreliance mitigation, fail-closed verdicts |
| Blast Radius Containment & Entity State Machine | MS-2.6-003 (re-evaluate when risk exceeds tolerance), bounded autonomy, HitL on TIER-1 |
| Cascading LLM Failover & Sovereign Degradation | GV-6.2-006 (rollover/fallback), fail-safe default verdict, availability |
| Durable Worker Circuit Breaker & DLQ | MS-2.6-005 (handle/recover/repair on anomaly), MG-2.3-001 (recovery plans) |
| Idempotent SOAR + Redis dedup; Concurrency Locking; Endpoint Identity regex; Vector Dimensionality Validation | Information Security baseline (input validation, replay/DoS bounding, UEBA-index integrity) |

This is a credible **MEASURE-2.7 (security & resilience)** implementation. The gaps below are concentrated in the **MEASURE-2.11 (bias), MAP/MEASURE privacy, Value-Chain governance,** and **GOVERN process** areas that the team has not yet built because they fall outside the "stop the prompt injection" framing.

---

## 3. Material gaps (prioritized)

### P1 - Harmful Bias & Homogenization (🔴 Risk 2.6)
The system makes **autonomous containment decisions**, so disparate behavior across subgroups is an allocative harm, not just a quality issue.

- **No disparity evaluation.** Nothing measures whether the swarm systematically over- or under-flags by OS family, business unit, asset class, geography, or non-English hostnames/identifiers. NIST **MS-2.11-001/002/004** (fairness assessment, disaggregated metrics, sources of bias) are unimplemented.
- **Immunity-memory feedback = homogenization / model-collapse vector.** The RAG immunity loop (`_persist_memory` → supervisor recall → auto-dismiss) feeds the swarm's *own* prior verdicts back into future analysis. A wrong high-confidence FP can entrench a blind spot, and synthetic verdict signatures accumulating in `nexus_swarm_memory` is exactly the **MS-2.11-005 / GV-1.3-005** model-collapse concern. The `FP_CONFIDENCE_GATE` mitigates blast radius but **no metric monitors drift or homogenization** of the memory distribution over time.
- **Recommendation:** add a periodic fairness/disparity job over historical verdicts (disaggregated TP/FP rates); instrument the immunity memory for distribution drift and cap/expire signatures; document a model-collapse watch per GV-1.3-005.

### P2 - Value Chain & Component Integration (🟡→🔴 Risk 2.12)
Frontier models (Anthropic primary, Azure secondary) are **opaque, externally-versioned dependencies that drive containment**.

- Local weights are SHA-384-pinned, but **frontier models are not** version-pinned or behaviorally re-baselined. A silent provider-side model update can change verdict behavior with no gate - NIST **MP-4.1-007, MG-3.1-003** (re-evaluate fine-tuned/adapted/3rd-party models), **MG-3.1-005** (review model/system cards).
- No **SBOM / vendor SLA / incident-notification** terms captured for the frontier providers (GV-6.2-007), no third-party GAI inventory (GV-6.1-007).
- **Recommendation:** pin frontier model IDs/versions in `nexus.toml`; run the Deterministic Regression Gate against the frontier path on provider version change; record provider model cards + SLA/incident clauses; add the providers to a third-party GAI inventory.

### P3 - Confabulation evidence-grounding (🟡 Risk 2.2)
The Regression Gate catches OS-context hallucination and schema drift, and the Review Board disputes weak findings - but **confabulated *evidence* inside a confident verdict is not verified against ground truth**.

- An expert can cite a log line, ARN, or byte-count that does not exist in the lake; nothing forces every evidentiary claim to resolve to a real row (NIST **MS-2.5-003** verify sources/citations; **MS-2.9** explainability of the answer).
- No **confidence calibration** or **construct-validity / measurement-error model** for the `confidence` field that gates immunity and acquisition (**MS-2.13-001**).
- No **active-learning capture** of model-failure instances for continuous improvement (**MG-4.1-004**).
- **Recommendation:** add a grounding check in the Review Board (or response agent) that re-resolves each cited artifact against DuckDB/Qdrant before a TP is confirmed; log calibration (predicted confidence vs. realized correctness) on operator dispositions.

### P4 - Data Privacy of the RAG memory (🟡 Risk 2.4)
DLP egress scrubbing + training-data redaction are solid, but the **persistent `nexus_swarm_memory`** is unaddressed.

- Stored verdict signatures + embeddings can enable **membership inference / cross-incident leakage** (NIST **MS-2.10-001**); there is no **retention/expiry or decommission policy** for memory or cold-storage (**GV-1.7-002**), and no differential-privacy/anonymization on the memory vectors (**MS-2.2-004**).
- **Recommendation:** define retention + expiry for `nexus_swarm_memory`; document a decommission protocol; assess membership-inference exposure of stored embeddings.

### P5 - Human-AI Configuration measurement (🟡 Risk 2.7)
HitL circuit breaker, TIER-1 manual review, and fail-closed defaults are good *structural* controls, but the **human side is not measured**.

- Operator **automation-bias / over-reliance is not tracked** (MG-1.3-002, MP-3.4-005) - override velocity is watched only for *poisoning*, not for calibration of human trust.
- No **disclosure** that verdicts/reports are AI-generated to downstream consumers (MP-5.1-003, GV-3.2-003 acceptable-use).
- **Recommendation:** track override outcomes (was the human right?) to calibrate both the model and operator trust; stamp incident reports with an AI-generated provenance/disclosure banner.

### P6 - GOVERN & Incident-Disclosure process (🟡 cross-cutting)
The controls are technical; the **governance wrapper is largely undocumented**.

- No **AI system inventory** (GV-1.6-001/003), no written **GAI risk-tiering** (GV-1.3-001), no **AI-incident reporting/disclosure** process distinct from SOC alerting (GV-4.3-002, MG-4.3-001/002), no **TEVV document-retention** policy (GV-1.5-003), no **decommissioning** runbook (GV-1.7-001).
- **Recommendation:** stand up a lightweight AI system inventory entry per served model (A-D + frontier), a one-page GAI risk-tier statement, and an AI-incident after-action template (these are mostly documentation, low engineering cost).

### P7 - Environmental Impacts (🔴 Risk 2.5, low severity)
No measurement/estimation of training or inference energy/carbon (**MS-2.12-002/003**). Low operational risk but a literal profile gap; a one-time estimate + per-run inference accounting closes it.

---

## 4. Non-applicable risks (document the determination)

CBRN (2.1), Dangerous/Violent/Hateful (2.3), Obscene/CSAM/NCII (2.11), and most of Intellectual Property (2.10) and Information Integrity content-provenance (2.8) concern **public content generation**, which Sentinel Nexus does not do - it ingests adversary telemetry and emits internal verdicts. NIST still expects the **determination to be recorded** (GV-1.3-003 calls for a written test plan/response policy even to conclude a risk is out of scope). **Recommendation:** add a short "Applicability Determinations" appendix to [security_controls.md](security_controls.md) stating, per risk, why it is N-A, so an auditor sees a decision rather than an omission.

---

## 5. Remediation roadmap (effort vs. impact)

| Priority | Item | Type | Rough effort |
|---|---|---|---|
| P1 | Disparity/fairness job over verdict history; immunity-memory drift monitor + expiry | Engineering | M |
| P2 | Pin frontier model versions; regression-gate the frontier path on version change | Engineering | S-M |
| P3 | Evidence-grounding check in Review Board; confidence-calibration logging | Engineering | M |
| P4 | RAG-memory retention/expiry + decommission policy; membership-inference review | Eng + Doc | S-M |
| P5 | Override-outcome calibration metric; AI-origin disclosure on reports | Engineering | S |
| P6 | AI system inventory, GAI risk-tier statement, AI-incident after-action template | Documentation | S |
| P2/P6 | Frontier model-card + SLA capture; third-party GAI inventory | Documentation | S |
| P7 | Training/inference energy-carbon estimate | Documentation | S |
| N-A | "Applicability Determinations" appendix (CBRN/CSAM/violent/IP) | Documentation | S |

**Bottom line:** Sentinel Nexus is strong on the *adversarial-security* spine of AI 600-1 (Information Security, prompt-injection, supply-chain integrity of local weights) and on *bounded-autonomy* structural controls (fail-closed verdicts, HitL, review board). The genuine gaps are **(1) bias/homogenization measurement - sharpened by the autonomous-containment and immunity-memory feedback design, (2) frontier-model version governance, (3) confabulated-evidence grounding, and (4) the GOVERN/privacy-lifecycle/incident-disclosure paperwork** that turns the existing engineering controls into an auditable AI risk-management program.

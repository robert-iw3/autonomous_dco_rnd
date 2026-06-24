# lab_agentic_siem - Implementation Tracker

## Intent (production-quality end state)

Prove, before any stack integration, that the sovereign agentic swarm can analyze an
environment **from existing SIEM data alone - no Nexus sensors deployed** - run the **full
analysis gamut end to end**, and produce a **factual, defensible incident report + attack
graph + containment / eradication course of action** at a quality we would ship to a customer.

This lab is the proving ground for WS-J (`planning_docs/AGENTIC_SIEM_ANALYSIS_PLAN.md`). We do
not promote the logic into the live stack until the lab clears the production-quality bar
below against near-real-world data.

**Prerequisite, before any actual SIEM analysis:** the swarm must first be *trained* on the
extensive `detection_training/` resources via the mlops pipeline so its detection quality is
real. An untrained swarm cannot produce a factual incident report from raw SIEM rows. So
**Phase D (detection-quality training) comes first** - it is the foundation the analysis phases
(P2 onward) depend on.

Why it matters: day-zero value on estates that already feed a SIEM but have no Nexus sensors;
prove data-collection gaps + recommend sensor placement; environment pre-training/grounding for
the LLM where no network-tap sensor exists.

## Current state (honest)

**P0 scaffold only - PASSING (17 tests), NOT production-grade yet.** What exists today:
- 3 small mock SIEMs (Splunk/CIM, Elastic/ECS, Sentinel/KQL), a handful of events each (a few
  benign + one short attack chain).
- A **deterministic** analysis stand-in (not the real LangGraph swarm): pivot -> entity
  extraction -> attack graph -> verdict -> report, with the real WS-I containment protocol.
- Grounding, benign-discipline, read-only, coverage-gap, and detection_training/ corpus +
  mlops-spool tests.

This proves the *data flow and the shape of the logic*. It does NOT yet prove real-world
analysis quality. The gaps to close are P1-P5.

## Definition of "production-quality" (acceptance criteria - must all hold before promotion)

1. **Near-real-world data.** Each mock SIEM carries realistic volume and breadth: hundreds to
   thousands of events, dozens of hosts / users / cloud resources, days of timeline, full
   CIM/ECS field richness, and *several concurrent benign workloads* (auth, web, DNS, cloud
   API, scheduled jobs, admin activity) so signal must be separated from heavy noise.
2. **Multiple, varied attack scenarios** interleaved with the benign noise - at minimum:
   web-shell -> lateral, identity/IAM abuse, ransomware precursor, cloud cryptomining, data
   exfil, and a **cross-SIEM campaign** (one actor visible across endpoint + cloud + identity).
   Plus pure-benign windows that must yield zero findings.
3. **Full agentic swarm, end to end.** The REAL graph runs: supervisor routing -> host / net /
   cloud / nettap experts (each issuing its own SIEM pivot queries to corroborate/disprove) ->
   adversarial review board (fail-closed) -> response synthesis. LLM seams are either sovereign
   models or high-fidelity deterministic doubles that still traverse every node + tool call and
   exercise grounding, the verdict ladder, and the thoroughness gate.
4. **Factual incident report.** Every scenario has a ground-truth label (affected assets, attack
   path/MITRE, correct verdict, correct containment set). The report is scored against it:
   entity precision/recall, attack-graph edge correctness, verdict accuracy, MITRE coverage,
   timeline correctness, and a complete + correct containment/eradication set per affected
   host/workload/identity/resource - with **zero benign assets contained**.
5. **Measured quality, regression-gated.** Detection precision/recall/F1, FP rate against the
   benign volume, report-completeness score, and analysis cost/latency are computed and gated
   (reuse the WS-A benchmark harness) so quality cannot regress.
6. **Read-only + safety throughout** (no mutating query reaches any SIEM; rows untrusted-wrapped;
   containment gated by the per-entity assurance + blast-radius breaker).
7. **Trained detection quality (Phase D).** The swarm models are trained on the
   `detection_training/` corpus and pass a detection eval gate (held-out rule precision/recall,
   query validity, result-analysis accuracy) - the analysis quality in 1-4 is measured on the
   *trained* swarm, not an untrained one.

## Roadmap (status: [ ] todo  [~] in progress  [x] done)

| Phase | Goal | Status |
|---|---|---|
| **P0** | Logic scaffold: mock SIEMs + deterministic analysis + real containment + validity tests | [x] |
| **D (prereq)** | mlops **detection-quality training pipeline** from `detection_training/` (sigma/kql/yaral/splunk/elastic/datadog/sentinel_one/suricata/trellix): ingest -> training corpus (detection comprehension, query authoring, result analysis, cross-dialect translation) -> train + eval the swarm's detection model(s) -> detection quality gate. **Must precede P2+** (the analysis is only as good as the trained detector) | [ ] |
| **P1** | Near-real-world datasets: high-volume, multi-host/user/resource, multi-day, rich CIM/ECS, heavy benign noise + several attack scenarios (incl. a cross-SIEM campaign) | [ ] |
| **P2** | Run the REAL agentic swarm graph end to end against the mock SIEMs (experts issue their own pivot queries; review board; response), LLM seams as the **Phase-D-trained** sovereign models or high-fidelity doubles | [ ] |
| **P3** | Ground-truth scenario labels + factual-report scoring (entity P/R, attack-graph edge correctness, verdict accuracy, containment completeness, zero benign contained) | [ ] |
| **P4** | Cross-SIEM correlation: one campaign stitched across endpoint+cloud+identity into a single incident + unified course of action | [ ] |
| **P5** | Quality metrics + regression gate (precision/recall/F1, FP rate, completeness, cost) via the WS-A benchmark harness; promotion checklist | [ ] |
| **P6** | Promote refined logic into the stack (WS-J J0-J5) once P1-P5 are green | [ ] |

## Detection-quality training pipeline (Phase D detail - the prerequisite)

Goal: turn the extensive `detection_training/` content into training signal that makes the
swarm genuinely good at detection + SIEM analysis, then gate that quality - before the lab
proves analysis on the trained swarm.

- **Resources (already in-repo):** `detection_training/` - Sigma rules, ~527 KQL queries, ~270
  YARA-L rules, plus Splunk / Elastic / Datadog / SentinelOne / Suricata / Trellix detection
  content and their pipelines. Rich MITRE tags, FP-sensitivity notes, logsource/product.
- **mlops wiring:** add a detection-training track to `mlops/scripts/01_spool_datasets.py`
  (the WS-J "Track 9", elevated to a prerequisite) that spools four example families:
  1. **Detection comprehension** - rule -> what it detects, MITRE, FP sensitivity, affected
     logsource.
  2. **Query authoring** - (intent, target dialect) -> a valid, read-only, bounded query.
  3. **Result analysis** - (result rows + CIM/ECS schema) -> finding (TP/FP), affected
     entities, MITRE, recommended containment class.
  4. **Cross-dialect translation** - Sigma -> SPL / KQL / ES|QL (and back) to generalize.
- **Train / merge / serve:** feed the existing pipeline (`02_train_*` -> `04_merge_weights` ->
  `05_serve_*`) for the model(s) that own detection/analysis (Model C endpoint + the analysis
  path), so the swarm loads the trained detector.
- **Eval gate:** a `detection_analysis` benchmark in `mlops/benchmarks/registry.toml` on a
  held-out rule split - query validity (parses + read-only + bounded), MITRE recall, and
  result-analysis verdict accuracy - gated by the M-24 regression gate; leakage scan ensures
  held-out rules never appear in the SFT set.
- **Output:** trained detection model(s) + a green detection eval. P2 runs the lab's swarm on
  THESE models; analysis quality (P3) is measured on the trained swarm.

## Mock SIEM data requirements (P1 detail)
- Volume: O(10^3) events/SIEM across a multi-day window; realistic per-source mix.
- Breadth: dozens of hosts (servers, workstations, DCs), users (human + service), cloud
  resources (instances, roles, buckets), networks/segments.
- Benign realism: normal logons, web 2xx/3xx, recursive DNS, patch/cron jobs, CI/CD, admin
  sessions, cloud autoscaling - the stuff that generates plausible false-positive bait.
- Scenarios: each is a labeled, time-correlated chain embedded in the noise; some span SIEMs.
- Fidelity: CIM (Splunk) and ECS (Elastic/Sentinel) field shapes match the real `SIEM_SCHEMA`.

## Full-swarm requirement (P2 detail)
- Drive the real `analytics/llm_hunter` graph; the SIEM pivot tool is the experts' read path,
  backed by the mock SIEM transport (WS-G already supports an injectable transport).
- Deterministic doubles for the LLM must still: route through supervisor, call expert tools
  (issue SIEM queries), populate the entity board, pass grounding, run the review board, and
  reach the response node - i.e. exercise the whole gamut, not a shortcut.

## Factual-report validation (P3 detail)
- Per scenario: `expected = {assets, attack_path, mitre, verdict, containment_targets}`.
- Score: entity precision/recall >= threshold, every expected attack-graph edge present,
  verdict exact, MITRE recall >= threshold, containment set == expected (no missing, no benign).
- Negative cases: pure-benign windows must produce no incident and no containment.

## Open questions / refinement notes
- Sovereign models vs deterministic doubles in CI (cost/latency vs fidelity) - likely doubles in
  CI, a periodic real-model run for the quality gate.
- Service-account containment policy (e.g. auto-disabling `www-data`) - certainty floor by
  account type; decide before promotion.
- Standardize the attack-graph schema (nodes/edges/MITRE) for promotion + cross-SIEM merge keys.
- How much real SIEM result variety to synthesize vs sample from `detection_training/`.

# SOAR / IR — Logic · Calls · Execution · Data Flow

A stage-by-stage trace of the path from detection to playbook execution: the
functions called, the NATS subjects crossed, the data shape at each hop, and how
the proven IR toolkit is driven and fed back to the swarm.

Overview: **[SOAR_IR_WORKFLOW.md](SOAR_IR_WORKFLOW.md)**.

---

## Stage 0 — Detection → investigation

| Step | Where | Data |
|---|---|---|
| L1/L2 emit alert | `worker_qdrant`, `worker_rules` → `nexus.deterministic.alerts` | `UnifiedAlertSchema` |
| Swarm launch | `orchestrator.trigger_swarm` (concurrency-sema, canary, `asyncio.wait_for`) → `build_graph` | `InvestigativeState` |
| Investigate | `supervisor → {host,net,cloud,nettap}_expert → review_board → response_agent` | typed entities accrue in `state["entities_of_interest"]` |

---

## Stage 1 — Plan the response (`agents/playbook_planner.py`)

`build_playbook_plan(alert, verdict, entities, memory_enriched, memory_threat)`:

- `infer_os_family(alert)` — source_type → `windows` / `linux` / `None`.
- `extract_iocs(entities)` — malicious-only, typed: `c2_ips, c2_domains, pids, hashes, file_paths, users`.
- `plan_response_waves(...)` → `wave1 = [isolate_host, collect_forensics]`, `wave2 = [block_ip, eradicate_process, eradicate_persistence]`.
- `actions_for_phase(waves, memory_enriched, memory_threat)` — first pass returns wave 1; the memory-enriched re-entry returns wave 2 only when `memory_threat`.

Cloud/network targets and monitor/dismiss verdicts initiate no on-host playbook.

**In parallel**, `build_containment_protocol(alert, verdict, entities, mem)`
(`agents/containment_protocol.py`) synthesizes the tailored cross-class protocol: per-TP-entity
steps chosen from the capability contract (`operations/infra/capability_matrix.toml` — endpoint,
cloud instance/workload, container, network resource, identity/credential), evidence-first and
kill-chain ordered, with a coverage gate (`kill_chain_closed` only when every TP entity has an
executable step or an explicit escalation), a per-entity assurance gate, lateral unification, per
(incident, target, action) idempotency keys, and a rollback builder for FP-flips.
See [SOAR_IR_WORKFLOW.md](SOAR_IR_WORKFLOW.md) §7.

---

## Stage 2 — Response payload + dispatch

`response_agent` builds `action_payload`:

| Field | Meaning |
|---|---|
| `action_type` | primary action (`isolate_host`, or `manual_review_required` if demoted) |
| `targets` | hosts only — alerting sensor + malicious `ip` entities (≤5, ATLAS cap) |
| `os_family`, `response_actions` | the wave's ordered host playbooks |
| `c2_ips · c2_domains · pids · hashes · file_paths · users` | typed IOC params |

The payload also carries the protocol fields: `environment`, `target_class`,
`containment_steps` (the cross-class steps worker_soar dispatches), plus audit extras
(`kill_chain_closed`, `containment_escalations`, `containment_coverage`).

HitL circuit breaker (`should_demote_to_manual`) → on trip, `manual_review_required`,
`response_actions = []`, **and every containment step is forced to
`gate = operator_approval`** — the full plan is preserved for the operator but nothing
auto-fires. `orchestrator._dispatch_soar` validates against `SoarExecutionSchema` and
publishes `model_dump()` to **`nexus.soar.execute`**.

---

## Stage 3 — worker_soar routing (`services/worker_soar`)

Deserializes `SoarPayload`, TTL-dedups by `(incident_id, action_type)`, routes.
**Protocol mode** (`containment_steps` non-empty) supersedes the legacy single-action
dispatch: each step is rendered to its executor — auto provider steps (cloud lambda /
Identity-DNS-K8s n8n workflows) and signed agent tasks per on-host step — while
`operator_approval`-gated steps are logged for the operator, never auto-dispatched.

| Path | Condition | Mechanism |
|---|---|---|
| Protocol steps | `containment_steps` non-empty | per-step: auto provider render or signed agent task; legacy single-action disabled |
| Cloud | cloud `source_type` (legacy mode) | n8n cloud-containment provider |
| On-host agent | on-prem + agent executor + `is_response_action` (legacy mode) | one **signed task per `response_action`** → `nexus.agent.tasks` |
| EDR/firewall n8n | on-prem schema provider (legacy mode) | ExecutionPlan steps → n8n |
| Legacy SSH | fallback | `run_containment.sh` |

`agent_task::build_signed_task` HMAC-signs each task; `action_targets_and_params`
sets the per-action `targets` + IOC params (only non-empty). Signing is
byte-identical to the Python `response_executor.sign_task` (golden-pinned).

---

## Stage 4 — On-host execution (`operations/agent/response_executor.py`)

The outbound-only agent polls `core_ingress GET /api/v1/tasks`, verifies the HMAC,
maps `action_type` → a fixed bundled playbook, and runs it with the `IR_*` env the
playbooks read (same contract `run_containment.sh` exports):

| action | playbook | `IR_*` env |
|---|---|---|
| `collect_forensics` | `00_collect_forensics.{sh,ps1}` | `IR_INCIDENT_ID`, `IR_HOST` |
| `isolate_host` | `01_contain_host.{sh,Contain-Host.ps1}` | `IR_MGMT_IPS` |
| `eradicate_process` | `02_eradicate_process.{sh,…}` | `IR_MALICIOUS_PIDS/PROCESSES/HASHES` |
| `eradicate_persistence` | `03_eradicate_persistence.{sh,…}` | `IR_MALICIOUS_PATHS/HASHES` |
| `block_ip` | `04_block_c2.{sh,…}` | `IR_C2_IPS` (targets), `IR_C2_DOMAINS` |
| `restore` | `06_restore.{sh,…}` | — |

Collection runs `Invoke-IRCollection` (forensics + memory capture). Each
orchestrator writes `reports/<host>/_status.json` (`status` + `tp_count`) and the
agent reports outcome on **`nexus.soar.callback`**.

---

## Stage 5 — The DFIR platform's findings → projection → enrichment

Memory/IR evidence is its **own data class**, and this stack does not hold it. The DFIR
platform collects the RAM image, seals it, stores it in its enclave and adjudicates it with
the toolkit both projects share. What crosses into the swarm is a **projection**: adjudicated
findings and their run context, sealed and allow-listed. The image never leaves the platform,
so nothing here has to be trusted with it — and there is no path from here into the platform's
enclave, only a pull from its DMZ edge.

The wire format, the direction, and what may never appear in a bundle are specified in
[`integrations/dfir_platform/PROJECTION-CONTRACT.md`](../integrations/dfir_platform/PROJECTION-CONTRACT.md).

| Step | Where | Data |
|---|---|---|
| RAM capture | the platform's collector / `Invoke-IRCollection --capture-memory` | `.aff4` / `.raw` / `.lime` image + `reports/<host>/`, sealed |
| Ingress, storage, analysis | **the platform**: one-way ingest into its enclave, its object store, `Analyze-Memory{.ps1,-Linux.sh} --adjudicate` | `Memory_Findings_<stamp>.json` (shared schema) + `_status.json` |
| Projection published | the platform writes a sealed bundle outward to its DMZ edge | run context + adjudicated findings; no image bytes, no object keys |
| Pull + verify | `worker_memory` pulls from the dispatcher (or a media drop) and checks the **HMAC-SHA256 seal first**, then the allow-list — flat, bounded, verdicts on the shared ladder (`dfir_platform.contract`) | refusal → **`nexus.dlq.memory_projection`** with the reason |
| Enrich | `to_enrichment` (TP-class via verdict ladder; `memory_threat` from TP-class or `tp_count`) → **`nexus.memory.enrichment`**, carrying `projection_id` + `platform_run_id` + `custody_verified` | advisory evidence, `source=memory_forensics` |
| Re-delivery | a bundle's id is the hash of its payload, so a republished run yields no second enrichment | idempotent by construction |
| Retention, legal hold, purge | **the platform's**, along with the audit record of each | not this stack's duty |

The swarm re-ingests the enrichment; `response_agent` reads
`state["memory_enrichment"]` → `build_playbook_plan(..., memory_enriched=True,
memory_threat=...)` → Wave 2 eradication if a TP-class verdict warrants it.

---

## Stage 6 — Lateral-movement fan-out (`agents/lateral_movement.py`)

After memory confirms the compromise:

```
plan_lateral_response(entities, origin_host, parent_incident, source_type, memory_threat):
    connected_internal_peers(...)   # RFC1918, deduped, origin/infra excluded
    plan_fanout(peers, MAX_FANOUT_HOSTS)   # cap; overflow → operator
    build_fanout_alerts(...)        # UnifiedAlertSchema-shaped, carry parent_incident
```

Each synthetic alert re-enters at Stage 0; `correlate_campaign.py` stitches the
hosts into one `Campaign_Report`.

---

## Subjects & artifacts

| Subject / file | Producer → Consumer | Payload |
|---|---|---|
| `nexus.deterministic.alerts` | L1/L2 → orchestrator | `UnifiedAlertSchema` |
| `nexus.soar.execute` | orchestrator → worker_soar | `SoarExecutionSchema` |
| `nexus.agent.tasks` | worker_soar → on-host agent | signed response task (per action) |
| `nexus.soar.callback` | agent → orchestrator | execution outcome |
| `POST /api/v1/evidence` | agent → core_ingress gateway | RAM image; JWT + HMAC + SHA-256 custody verified |
| `nexus.memory.intake` | gateway → worker_memory | verified handle `{incident_id, host, os_family, kind, sha256, s3_key}` |
| `nexus.memory.enrichment` | worker_memory → swarm | adjudicated memory findings + `tp_count` |
| WORM `memory/<incident>/<host>/image` | gateway (verified) | GOVERNANCE-locked image (operator-purgeable) |
| `reports/<host>/_status.json` | IR orchestrator | `status` + `tp_count` (SOAR gate) |
| `IOCs.json` / `Principals.json` | adjudication | eradication inputs |
| WORM S3 `memory/<incident>/<host>/{image,findings,status}` | worker_memory | immutable historical reference |

## Shared contracts

- **Finding schema** (`reporting/finding_schema.py`): `Type`, `Target`, `Verdict` (ladder), `MITRE` — case-insensitive; every platform conforms.
- **Verdict ladder**: False Positive → Likely FP → Indeterminate → **Likely TP / True Positive** (TP-class, the eradication gate).
- **`_status.json`**: `{incident_id, hostname, platform, status, phases, tp_count}`.

## Tests

| Layer | Test |
|---|---|
| planner (IOCs, waves, phase gate) | `tests/lab_analytics_hunter/test_playbook_planner.py` |
| response payload + two-phase + HitL | `tests/lab_analytics_hunter/test_response_playbooks.py` |
| lateral-movement fan-out | `tests/lab_analytics_hunter/test_lateral_movement.py` |
| SoarExecutionSchema fields/validator | `tests/lab_agentic_swarm/test_agentic_swarm_contracts.py` |
| worker_soar signed-task contract | `tests/test_worker_contracts.py` |
| agent executor (`IR_*`, playbook map) | `tests/lab_operations_contracts/test_response_executor.py`, `test_task_dispatch.py` |
| worker_memory (routing, schema, WORM, orchestration) | `tests/lab_memory_forensics/test_memory_analysis.py` |

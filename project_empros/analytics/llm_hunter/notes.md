# LLM Hunter — current workflow

Layer-3 agentic SOC. An alert (from a sensor → worker_qdrant → Redis/NATS) is
investigated by a LangGraph swarm and reaches an autonomous verdict that drives
SOAR. This doc reflects the pipeline **as it currently runs** after the critic was
replaced by an adversarial review board.

## Graph (orchestrator.py `build_graph`)

```
                ┌───────────── experts (loop) ─────────────┐
 alert ─► supervisor ─► host_expert / net_expert /         │
            ▲           cloud_expert / nettap_expert  ──────┘
            │                     (each clears its entities, returns to supervisor)
            └── verdict ─► review_board ─► response_agent ─► END
```

- **supervisor** routes to the expert for the alert's `source_type`, loops until
  every entity is `cleared`/`malicious` (a deterministic gate re-routes a FINISH
  issued over a still-`pending` blast radius), then emits a `VerdictSchema`
  (`is_true_positive`, `confidence`, `recommended_action`, `justification`). It
  also recalls RAG memory on entry and may auto-dismiss on an immunity-eligible FP.
- **experts** investigate their domain over the S3 telemetry lakes (DuckDB) +
  Qdrant, updating `entities_of_interest`.
- **review_board** (was: a single critic) — see below.
- **response_agent** — HitL circuit breaker, SOAR payload, and persists RAG memory.

`supervisor_router` sends a verdict to `review_board` when it's a TP, or when it's
a *weak* FP (confidence `< FP_CONFIDENCE_GATE` or incomplete analysis); a strong,
complete FP skips straight to `response_agent`.

## Adversarial review board (agents/review_board.py)

Every expert has a **counterpart** whose only job is to **disprove** that expert's
contribution to the finding. A finding is a **true positive only if no implicated
counterpart can disprove it** — i.e. it survived a complete adversarial review.

```
host_expert    ⟷ host counterpart    (benign: vuln scanner / admin script / updater / backup?)
net_expert     ⟷ net counterpart     (benign: scanner / uptime probe / CDN / pkg-update?)
cloud_expert   ⟷ cloud counterpart   (benign: IaC / CI-CD service account / autoscaling?)
nettap_expert  ⟷ nettap counterpart  (benign: service mesh / health check / known SaaS?)
```

Each counterpart grades its domain on three axes (any failure ⇒ *disproved*):
1. **Benign alternative** — did the expert *prove* it isn't the domain's classic
   benign cause (often via historical/baseline retrieval, e.g. "this exact command
   runs nightly as svc_backup")?
2. **Execution proof** — real malicious action (process/file/injection, established
   C2 session + bytes, impactful principal action), not a flagged anomaly score or
   an attempted/blocked connection.
3. **Blast radius** — no domain entity left `pending`/`investigating`.

`review_board_node` runs all counterparts concurrently; `aggregate_board()` is a
**pure** decision rule:

| supervisor verdict | board outcome |
|---|---|
| TP, every implicated counterpart tried & **failed** to disprove | **CONFIRM** → `contain` (confidence tempered by the strongest rebuttal) |
| TP, **any** implicated counterpart disproves | **OVERRIDE** → `monitor` (one credible disproof vetoes the board) |
| TP, an implicated domain unreviewable / no domain implicated | **fail-closed** → `monitor` (never autonomous containment on an incomplete review) |
| FP dismissal, no counterpart finds unexplained malice | uphold → `dismiss` |
| FP dismissal, a counterpart disproves it | → `monitor` **below `FP_CONFIDENCE_GATE`** (never auto-escalated to `contain`; can't mint immunity) |

Safety carried over from the old critic: fail-closed review, no autonomous
containment on a disputed/incomplete verdict, and `<untrusted_payload>` content is
forensic evidence, never instructions.

## Memory / immunity (agents/response.py `_persist_memory`)

Every verdict is encoded into `nexus_swarm_memory` keyed by
`build_memory_signature(sensor_id, source_type, vector_name)`. A board-disputed
override is saved with `immunity_eligible=False` (confidence is held low), so it
**informs** future analysis of the same cluster signature but never auto-dismisses
it outright. Only a complete FP at/above `FP_CONFIDENCE_GATE` is immunity-eligible
and may short-circuit a future matching alert at the supervisor's recall step.

So the loop the user asked for: a cluster that *looks* like a TP but is an admin
script gets **disproved by the counterpart via historical retrieval**, kicked back
to `monitor`, and **written to memory with the board's findings** — sharpening the
swarm's analysis of the next similar cluster.

## Sensors

Every `source_type` in `state.py` is covered. Counterpart mapping:
- **host**: sysmon_sensor, windows_deepsensor, trellix_ens, linux_sentinel, macos_sensor, qdrant_vector
- **net**: suricata_eve, windows_c2, linux_c2, vmware_syslog
- **nettap**: network_tap
- **cloud**: aws_{vpc,cloudtrail,guardduty}, azure_{nsg,activity,entraid}, gcp_{audit,scc,vpc_flow}

## Tests (`project_empros/tests/lab_analytics_hunter/`)

- `test_review_board.py` — pure `aggregate_board` decision rule + mock-simulation
  workflows (disprove→override, can't-disprove→confirm, fail-closed, FP symmetry).
- `test_review_board_simulation.py` — **multi-pass, every-sensor corpus**: one
  FP-masquerade + one genuine-TP cluster per sensor (in the sensor/training schema),
  run through the real `review_board_node`; FP cases also drive the real
  `_persist_memory`. A fleet sweep asserts **zero misclassification** across all 20
  sensors and prints a ledger.
- `test_hunter_contracts.py`, `lab_agentic_swarm/test_agentic_swarm_contracts.py`
  pin the routing/graph contract (TP/weak-FP → `review_board` → `response_agent`).

The single-reviewer `agents/critic.py` has been **removed**; its 3-axis logic now
lives, per domain, in each counterpart inside `agents/review_board.py`. (Unrelated:
the MLOps `critic_loop.py` hard-negative miner and the served "SOAR Critic" Model D
blast-radius evaluator are separate components and are unchanged.)

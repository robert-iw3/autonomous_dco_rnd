# MLOps Maturation Plan: Embedded Benchmarking, Evaluation QA, Fail-Fast Learning, and Training/Serving Plane Separation

**Status:** PLAN (current beta testing gap analysis @RW)

**Date:** 2026-06-09

**Builds on:** P15 deep-analysis loop (thoroughness gate, symmetric critic, immunity eligibility) and RSI loop memory (`rsi_ledger_v1.jsonl`, regression gate M-24, score export M-25)

**Tracked in:** [planning_docs/BACKLOG.md](../planning_docs/BACKLOG.md) → workstream **WS-A** (proposed IDs M-26…M-34, Q-19…Q-21). This document is the design authority; the backlog is the status authority.

---

## 1. Problem Statement

The pipeline can train, gate, and deploy the four-model swarm, and (post-P15) the RSI loop
remembers its own cycles. What it cannot yet answer:

1. **"Is the swarm getting better at investigations?"** — Eval gates score *models* on frozen
   datasets at training time. Nothing scores *investigations* in production over time. Verdict
   quality, thoroughness, cost, and operator agreement are invisible between deployments.
2. **"Are our evaluations themselves trustworthy?"** — Benchmark datasets have no leakage
   control against the training corpus, no balance audit, no judge-calibration check, and no
   reproducibility contract. A green gate proves the model passed *our* test; nothing proves
   the test still measures what we think it measures.
3. **"How fast do we learn from a miss?"** — A missed detection today reaches retraining only
   when an operator dismissal lands in Track 5 and a ≥50-verdict batch accumulates. There is
   no measured **time-to-learn**, no shadow evaluation of candidates on live traffic, and no
   fast canary check before burning a full gate cycle.

The maturation goal: **benchmarking embedded in the feedback loop** — every investigation
emits metrics, every closed investigation can become a benchmark case, every deployment is
judged against the live metric trend, and every failure shortens the path to the next
training batch.

---

## 2. Architecture: the metric loop inside the AI loop

The five-step loop (trigger → context → action → check → memory) gains a parallel
measurement plane. Every step emits; nothing new blocks the hot path.

```
                        ┌──────────────────────────────────────────────────────┐
                        │              MEASUREMENT PLANE                       │
                        │                                                      │
 swarm investigation ──►│ InvestigationMetrics record (§3.4)                   │
 (orchestrator/response)│   nexus.metrics.investigation (NATS)                 │
                        │   └─► investigation_metrics_v1 (parquet ledger)      │
                        │   └─► Prometheus counters/histograms (existing)      │
                        │                                                      │
 operator action ──────►│ Outcome join (§3.4): worker_rlhf labels +            │
 (worker_rlhf)          │   SOAR callbacks + 24h re-infection check            │
                        │   └─► delayed ground truth per investigation         │
                        │                                                      │
 closed investigation ─►│ Replay Bench candidate (§3.3): alert + data slice    │
                        │   + entity graph + adjudicated label, frozen         │
                        │                                                      │
 RSI cycle ────────────►│ 09_benchmark_runner.py (§3.1) scores candidate       │
 (08_rsi_loop.py)       │   └─► RSI_EVAL_SCORES_FILE (M-25 contract)           │
                        │   └─► regression gate vs deployed baseline (M-24)    │
                        │   └─► rsi_ledger_v1.jsonl gate_scores (P15)          │
                        │                                                      │
 promotion ────────────►│ Shadow/canary comparison (§5.2) + live-metric        │
 (registry, §6)         │   rollback trigger (§5.3)                            │
                        └──────────────────────────────────────────────────────┘
```

The key inversion: today the eval gates *produce* a pass/fail and discard the numbers.
After this plan, **every number lands in a ledger keyed by model version and time**, and the
deploy decision, the rollback trigger, and the corpus-generation priorities all read from
the same ledgers.

---

## 3. Pillar 1 — Benchmark Registry & Harness

### 3.1 Benchmark runner and registry

New: `mlops/scripts/09_benchmark_runner.py` + `mlops/benchmarks/registry.toml`.

* **Registry** declares each benchmark: id, version, capability axis, dataset path
  (`mlops/benchmarks/<id>/v<N>/`), scorer, target (model A/B/C/D, swarm-e2e), runtime budget,
  and whether it gates deploys or only trends.
* **Runner**: one CLI, `--bench <id|tier>`, `--target <endpoint>`,
  `--config <quant-config>`; emits one `BenchmarkResult` JSONL row per case and one
  aggregate row per run into `mlops/data/benchmark_runs_v1.jsonl`; also writes the flat
  `{metric: float}` file consumed by the M-24 regression gate (this **completes M-25** — the
  benchmark harness becomes the score producer the RSI loop is already waiting for).
* **Tiers** (fail-fast ordering, see §5.1):
  * `tier-0 canary` — ≤5 min, ~100 cases, every checkpoint, hard gate.
  * `tier-1 capability` — ~30 min, full per-model suites, every RSI cycle, regression-gated.
  * `tier-2 e2e` — hours, swarm-level replay + adversarial, weekly + before any production swap.

### 3.2 Capability axes (what gets benchmarked)

Mapped to existing assets so v1 is mostly *formalization*, not new data:

| Axis | Target | Seed data (exists today) | New in this plan |
|---|---|---|---|
| Verdict accuracy (TP/FP per source_type) | Model C / swarm | golden datasets, hard-negative matrix | per-source_type breakouts, partial credit |
| Hard-negative discrimination | Model C/D | `hard_negatives_sft_v1`, operator HNs | held-out HN split never used in training (§4.1) |
| TTP / kill-chain sequencing | Model C / swarm | `cross_source_temporal_v1`, `kill_chain_sft_v1` | ordering/causality scoring, multi-event cases |
| L7 forensic quality | Model B | Track 4 gates (≥95%) | graded rubric instead of threshold-only |
| Governance determinism | Model D | `03_eval_critic.py` Phases 1–4 | trend export, cohort drill-down |
| Injection/adversarial robustness | all + swarm | garak, PyRIT, CognitiveBypass | scores trended per release, not just pass/fail |
| Investigation thoroughness | swarm-e2e | **new** — Replay Bench (§3.3) | gate-override rate, entity-resolution ratio, evidence citation |
| CTI distillation | TI/RAG path | OpenCTI mirror, worker_ti_ingest corpus | report→IOC/TTP extraction set |

### 3.3 Investigation Replay Bench (the biggest lever)

Every closed investigation already contains everything a benchmark case needs: the
`UnifiedAlertSchema` trigger, the Parquet slice the experts queried, the entity board with
terminal statuses, the verdict, and — within days — the operator adjudication and SOAR
outcome. Freeze it:

* `10_freeze_replay_case.py` packages `{alert, data_slice (DuckDB-extractable subset),
  entity_graph, adjudicated_label, operator_rubric?}` into `mlops/benchmarks/replay/v<N>/`.
* Selection policy: all operator-overridden cases (the misses — highest value), a stratified
  sample of agreed cases, and every `manual_review_required` escalation.
* Scoring: verdict correctness (graded, not binary — correct verdict with wrong entity
  attribution scores between full credit and zero), blast-radius recall (entities found vs
  adjudicated graph), evidence grounding (every claim in the incident report must be
  traceable to a tool output in the frozen data slice — explainable ground truth), and
  efficiency (turns, tokens, tool errors).
* This makes the benchmark **dynamic by construction**: the suite grows from live traffic,
  and rotates quarterly with dedup (§4.1).

### 3.4 Per-investigation metrics (the embedded part)

New record emitted at the end of `trigger_swarm` (fire-and-forget, never blocks SOAR):

```
investigation_metrics_v1  (NATS nexus.metrics.investigation → parquet ledger)
  event_id, ts, source_type, vector_name, anomaly_score, model_versions{}
  verdict{is_tp, confidence, action}, analysis_complete, gate_overrides_used
  critic{invoked, overrode, direction}, immunity{hit, point_id}
  entities{seeded, temporal_seeded, resolved, malicious, cleared}
  efficiency{turns, llm_calls, provider_fallbacks, tool_errors, tokens_est, wall_ms}
  outcome (joined later){operator_action, soar_status, reinfection_24h, label_latency_s}
```

Derived longitudinal metrics (Grafana panels + weekly roll-up into the ledger):

| Metric | Definition | What it tells us |
|---|---|---|
| Operator agreement rate | 1 − overrides/adjudicated | headline effectiveness, per source_type |
| FP burden | FP verdicts reaching operators / total | alert fatigue trend |
| Miss proxy | operator CONFIRM where swarm said FP + reinfection_24h after CONFIRM_QUARANTINE | detection efficacy |
| Thoroughness | gate-override rate, entity-resolution ratio, % verdicts `analysis_complete` | is the P15 gate biting; is the model learning to finish the board |
| Critic value | critic override rate split TP→FP vs FP-weak endorsements | is the check step earning its latency |
| Immunity precision | immunity hits later contradicted by operator | memory-step safety |
| MTTV / cost | median wall time, tokens, provider fallbacks per verdict | efficiency regression detection |
| **Time-to-learn** | miss adjudicated → weights deployed that fix its replay case | §5 fail-fast headline KPI |

Joining keys already exist: `event_id` flows through worker_rlhf (`nexus.training.rlhf`)
and SOAR callbacks (`nexus.soar.callback`). The join job is a small batch script
(`11_join_outcomes.py`), not a new service.

### 3.5 Config-axis track (quantization × fine-tune)

Each tier-1 run records the target config `{base_model, adapter_version, quant}` so the
ledger can answer "did 4-bit NF4 cost us robustness on this release?" When an edge/quantized
variant is proposed (e.g., ONNX Model A, future smaller Model D), the same suite runs the
quant × fine-tune matrix before promotion.

### 3.6 Baseline ladder

Score context against: (a) base instruct model with no adapter, (b) previous deployed
adapter (already the M-24 baseline), (c) optionally one mirrored public security fine-tune
as an external reference point. (a) and (c) run quarterly, not per-cycle — they answer
"is fine-tuning still paying for itself?"

---

## 4. Pillar 2 — QA Harness for the Evaluations Themselves

Evaluations are code + data; they get the same QA discipline as the pipeline.

### 4.1 Dataset QA (per benchmark version, blocking its registration)

* **Leakage gate**: TurboVec near-duplicate scan (reuse `corpus_utils` dedup, threshold
  ~0.92) of every benchmark case against the *entire* training staging area — a bench case
  that resembles a training record is rejected. This is currently our biggest silent risk:
  golden-derived eval sets and training sets share generators.
* **Balance & coverage audit**: class balance per axis, MITRE tactic coverage map, per
  source_type counts; published as a manifest next to the dataset with SHA-384 (same
  integrity pattern as model manifests).
* **Refresh policy**: quarterly rotation; retired cases archived, never deleted
  (longitudinal comparability via an anchor subset that persists across versions).

### 4.2 Determinism & reproducibility

* All scored runs at temperature ≤0.1 with the M-10 consistency sweep extended to benchmark
  cases: any case with consistency <0.8 across N=4 samples is flagged `unstable` and scored
  by majority, reported separately from the stable population.
* `BenchmarkResult` rows carry `{bench_version, dataset_sha384, model_versions, seed,
  runner_git_sha}` — a score that can't be reproduced is a bug.

### 4.3 Judge calibration

The LLM-as-Judge ensemble (`04_reward_model.py --mode judge`, 40% rule / 60% LLM) currently
has no ground-truth check. Add: monthly sample of judge-scored verdicts double-scored by
operators using a weighted rubric (report quality 30%, evidence grounding 40%, action
appropriateness 30%); compute judge↔operator agreement (Cohen's κ); κ < 0.6 freezes
judge-weighted promotion until recalibrated.

### 4.4 Harness CI

* New `run_tests.sh` section `bench` (Dockerfile.bench): registry schema tests, scorer unit
  tests with fixture cases, leakage-gate tests, M-25 score-file contract tests, and a
  `--smoke` run of tier-0 against a stub model. Mirrors the existing offline-lab pattern
  (no GPU, no network).
* `validate_pipeline.py` gains checks: registry parses, every registered dataset has a
  manifest + passes SHA-384, every gate-marked bench has a scorer test.

---

## 5. Pillar 3 — Fail Fast, Learn Fast

Current loop latency: miss → operator dismissal → Track 5 spool → ≥50-verdict batch →
full train → full gates → deploy. Weeks, and the full gate cost is paid even for doomed
checkpoints. Three changes:

### 5.1 Fail fast — order the cheap checks first

* **Tier-0 canary bench** (≤5 min, ~100 cases: 25 hardest replay misses, 25 hard negatives,
  25 injection probes, 25 governance cases) runs **before** PPO/DPO completes its full gate
  sequence in `08_rsi_loop.py`: train → tier-0 → (fail ⇒ critic retune immediately, skip
  garak/PyRIT cost) → alignment gates → tier-1 + regression gate → deploy. The RSI ledger
  records tier-0 scores per attempt, so quarantine (M-23) can also trigger on tier-0
  patterns, not only full-gate failures.
* **Early-abort training**: existing per-head gradient tracking + early stopping stays;
  add a mid-training tier-0 probe at 50% steps for PPO runs (checkpoint already exists
  every 500 samples) — a checkpoint trending below baseline aborts the run.

### 5.2 Learn fast — shorten label-to-weights latency

* **Champion/challenger shadow mode**: candidate adapter served alongside production
  (vLLM second adapter or second container); the orchestrator mirrors a sampled fraction of
  investigations to the challenger (read-only — challenger verdicts are *recorded, never
  dispatched*; no SOAR, no memory writes). Disagreements with the champion are auto-queued
  for operator adjudication = highest-information labels first (uncertainty sampling).
* **Miss-driven micro-batches**: an operator override (miss or FP-burden case) immediately
  (a) freezes a replay case (§3.3) and (b) generates counterexamples via the existing
  critic loop into the next batch — without waiting for the 50-verdict threshold. The
  threshold remains for *full* retrains; micro LoRA deltas may train on ≥10 adjudicated
  misses but can only be promoted through the same tier-0 + alignment + regression gates.
* **Failure clustering → gap-driven corpus**: weekly job clusters benchmark/replay failures
  by `{MITRE tactic, source_type, vector_name}` (TurboVec embeddings, reuse HardNegativeMiner)
  and writes a ranked gap report into `mlops/todos.md` (the sigma-validate pattern). The
  next `stage_*` corpus work is pointed at measured gaps, not intuition.
* **Time-to-learn KPI**: ledger-computed `median(label_ts → deploy_ts of the cycle whose
  weights pass that case's replay)`. Target maturation: weeks → <72h for the micro-batch path.

### 5.3 Fail safe — live-metric rollback

`make deploy` already auto-rolls back on readiness probes. Extend to quality: for 24h
post-swap, compare the live metric stream (operator agreement, FP burden, MTTV, critic
override rate) against the pre-swap 7-day baseline with simple control bands (e.g., 3σ or
fixed floors); a breach pages the operator and (for the unattended RSI path) executes the
registry rollback (§6.4). The shadow-mode comparison (§5.2) is the first line; this is
the backstop when shadow traffic missed a regime.

---

## 6. Pillar 4 — Training/Serving Plane Separation & Model Registry

### 6.1 The coupling problem

Today `mlops/` is one plane: data staging, training, eval gates, the RSI loop, *and*
deployment share one directory, one dependency stack, and the analytics node's GPUs — and
`make deploy` runs **from the training context** with the power to symlink-swap weights and
restart `vllm-inference.service` in production. Three concrete failure modes follow:

1. **Detection latency coupling.** Investigations time out at `NEXUS_INVESTIGATION_TIMEOUT`
   (120s) and a timeout floods the manual-review queue. A ZeRO-3 run on the 24B Model B
   saturating the same GPUs as vLLM causes exactly that — a training job degrades live
   detection.
2. **Security blast radius.** The training plane handles the most dangerous material in the
   system (Firecracker detonation output, threat-feed mirrors, operator feedback, subprocess
   orchestration in `08_rsi_loop.py`) *and* holds write/exec power over production serving.
   Push-based deployment from that context is the wrong trust direction.
3. **Lifecycle entanglement.** Training churns trl/peft/deepspeed/unsloth versions; serving
   wants a stable vLLM. One stack means every training-dep upgrade risks the inference
   container, and a crashed training run shares a failure domain with detection.

### 6.2 Target topology

Three components with one contract between each pair:

```
┌─────────────────────────────┐      ┌──────────────────────────┐      ┌──────────────────────────────┐
│   TRAINING PLANE            │      │   MODEL REGISTRY         │      │   SERVING PLANE              │
│                             │      │  (S3/MinIO bucket        │      │                              │
│ stage_* / 01_spool          │      │   nexus-model-registry,  │      │ vllm-inference / vllm-critic │
│ 02_train_* / 04_reward      │ push │   versioned prefixes)    │ pull │ vllm-network / baseline-     │
│ 06_sandbox / 07_feed_ingest ├─────►│                          │◄─────┤ detector quadlets            │
│ 05_critic_loop              │      │ <model>/<version>/       │      │                              │
│ 09_benchmark_runner (§3.1)  │      │   weights|adapters/      │      │ model_steward (new):         │
│ 08_rsi_loop (ends at        │      │   manifest.json          │      │  subscribes                  │
│   PUBLISH, no deploy)       │      │   gate_scores.json       │      │  nexus.models.promote,       │
│                             │      │                          │      │  pulls, verifies, swaps,     │
│ NATS: nexus.models.promote ─┼──────┼──────────────────────────┼─────►│  probes, rolls back          │
└─────────────────────────────┘      └──────────────────────────┘      └──────────────────────────────┘
        full GPU bursts                  the only shared state            latency-stable, pull-only
```

The promotion message follows the existing `skill.update` hot-load pattern (NATS subject +
payload validated against a schema + consumer-side verification) — the codebase already
proves this handoff style works.

### 6.3 Registry contract (`manifest.json` per version)

```
nexus-model-registry/<model_id>/<version>/manifest.json
  model_id          "model_c" | "model_b" | "model_d" | "model_a"
  version           monotonic, timestamped (e.g. 20260609T2200-c41)
  base_model        hf_id + revision (from model_config.toml)
  artifact_type     merged_weights | lora_adapter | onnx
  quant             nf4-4bit | fp16 | onnx-int8 ...        (§3.5 config axis)
  sha384_manifest   full-directory integrity map (existing pattern, ATLAS AML.T0044)
  gate_scores       copied from rsi_ledger_v1.jsonl gate_scores for this cycle
  gates_passed      [tier0, garak, pyrit, regression, alignment]
  rsi_cycle_id      provenance link into the RSI ledger
  bench_versions    {bench_id: dataset_sha384} the scores were measured against
  promoted_at       ISO 8601 UTC
```

Promotion is **refused by the serving plane** unless: SHA-384 verifies, `gates_passed`
contains the full required set, and `gate_scores` are present (no scores, no swap — the
serving side re-enforces what the training side claims). Credentials via Vault
(`nexus/models/registry_key`), per-plane: training gets write-only to the registry,
serving gets read-only. Retention: keep N=3 versions per model + every version referenced
by a ledger `deployed` record.

### 6.4 Promotion, boot order, and rollback

* **Promotion (pull-based):** `08_rsi_loop.py` ends its cycle at *publish* — it uploads
  artifacts + manifest and emits `nexus.models.promote`. A new `model_steward` agent on the
  serving plane (small Python service, quadlet-managed like the vLLM containers) pulls,
  verifies (§6.3), atomic-symlink-swaps into the local model store, restarts the target
  vLLM unit, runs the readiness probe (existing 12×10s), and acks
  `nexus.models.promoted`/`nexus.models.rejected` so the RSI ledger records the real
  outcome. The training plane loses all exec/write access to serving — the current
  `make deploy` mechanics move into `model_steward`, they don't get rewritten.
* **Boot order — provisioning-first, not runtime-dependent:** "training loads first" holds
  at *provisioning* time: the deployment_prep bundle ships gate-passed baseline weights as
  registry version 0, so production never boots ungated weights. At *runtime* the
  dependency is inverted: serving boots self-sufficiently from its local last-known-good
  model store and never blocks on training-plane availability. Detection availability must
  not depend on learning availability. **Fail-open serving, fail-closed promotion** — the
  same asymmetry as the critic.
* **Rollback = re-pin:** rollback (readiness failure, or the §5.3 live-metric breach)
  becomes "re-pin previous registry version," symmetric with promotion and recorded in the
  ledger. The shadow champion/challenger (§5.2) is served the same way — a challenger is
  just a registry version pulled into a second adapter slot, which is why this pillar is a
  prerequisite for Phase B3.

### 6.5 Plane decomposition of today's `mlops/`

| Component | Plane | Notes |
|---|---|---|
| `stage_*`, `01_spool`, `corpus_templates/`, `06_sandbox_runner`, `07_feed_ingest` | training | data + detonation never touch serving |
| `02_train_*`, `04_reward_model`, `05_critic_loop`, `02_train_qlora --rlhf-mode *` | training | full GPU bursts allowed |
| `03_eval_*`, garak/PyRIT, `09_benchmark_runner` tier-0/1 | training | pre-promotion gates run where the candidate lives |
| `08_rsi_loop.py` | training | `make deploy` call replaced by publish (§6.4) |
| `04_merge_weights.py` + manifest generation | training | output goes to registry, not to a serving path |
| registry bucket + manifest schema | contract | the only shared state |
| `model_steward` (new), vLLM quadlets, `serve_vllm.sh`, `05_serve_*` | serving | pull, verify, swap, probe, rollback |
| tier-2 e2e smoke + live-metric rollback (§5.3) | serving | post-pull acceptance runs against the *served* endpoint |
| `skills_v1.jsonl` hot-load | unchanged | already follows this pattern |

### 6.6 Hardware: logical-first, physical when available

Sovereign deployments may have a single GPU node, so the split is **by contract first,
metal second**: separate quadlets, separate unix users, cgroup CPU/memory isolation, and
either scheduled training windows or MIG/`CUDA_VISIBLE_DEVICES` partitioning on shared
GPUs. Every interface above is identical when a dedicated training node arrives (already
the trajectory for the Model C 70B upgrade), so the physical split is a host-inventory
change in Ansible, not a redesign.

### 6.7 Trade-off summary

| | Split (this design) | Status quo (single plane) |
|---|---|---|
| Detection latency under training load | isolated (windows/MIG or separate node) | vLLM competes with ZeRO-3; investigation timeouts |
| Trust direction | serving pulls signed artifacts; training has zero exec into prod | training context restarts production services |
| Ungated weights in prod | impossible (steward refuses manifest without gates_passed) | possible via direct `make deploy` |
| Shadow/challenger (B3), live rollback (B4) | native (registry versions, re-pin) | requires ad-hoc filesystem juggling |
| Dependency lifecycles | independent bundles per plane | one stack; training churn risks inference |
| Failure domains | training crash invisible to detection | shared node/service blast radius |
| Cost | registry + steward + one more contract to test; 2 air-gap bundles | none (already built) |
| Drift risk | new seam — needs `lab_infra_contracts` coverage from day one | no new seam (but implicit coupling everywhere) |
| Learn-loop latency | +publish/pull step (automated, minutes) | direct swap |

The cost column is real but bounded: the registry is an S3 prefix scheme on the MinIO that
already exists, the steward reuses the current deploy/rollback code, and the contract-test
pattern is established. The implicit-coupling row is the deciding one — the status quo's
"no new seam" hides that training and serving are already coupled everywhere *without* a
tested contract.

### 6.8 Contract tests (non-negotiable, day one)

The P13 QA cycle proved cross-layer vocabulary drift is this project's dominant failure
mode. The registry seam ships with its contract suite or not at all:

* manifest schema round-trip + rejection tests (missing gates, bad SHA-384, unknown quant);
* `nexus.models.promote`/`promoted`/`rejected` subjects asserted in both publisher and
  steward source + NATS authorization config (training user: publish-only; steward:
  subscribe + ack publish);
* steward refuses unverifiable manifests; rollback re-pin restores byte-identical prior
  version; boot-from-local-cache works with the registry unreachable;
* `08_rsi_loop.py` source contract: no `make deploy` invocation remains.

---

## 7. Phased Roadmap

**Phase B0 — Contracts & plumbing (1 sprint)**
`InvestigationMetrics` schema + NATS subject + parquet ledger writer in the orchestrator;
`11_join_outcomes.py` (RLHF + SOAR join); M-25 closed via `09_benchmark_runner.py` skeleton
emitting the score file from the *existing* eval scripts; registry.toml + 2 registered
benches (hard-negative held-out, governance). `bench` CI section. *Acceptance: RSI
regression gate runs non-vacuously; Grafana shows live agreement/FP-burden panels.*

**Phase B1 — Replay Bench + tier-0 (1–2 sprints)**
`10_freeze_replay_case.py` + selection policy; 100-case tier-0 canary assembled; tier-0
wired into `08_rsi_loop.py` before alignment gates; leakage gate operational.
*Acceptance: a deliberately overfit adapter is caught by tier-0 in <5 min; replay cases
reproduce frozen verdicts bit-stable on the champion.*

**Phase B2 — Eval QA (1 sprint, parallel with B1)**
Dataset manifests + SHA-384, balance audits, consistency-sweep integration, judge
calibration sampling + κ gate, `validate_pipeline.py` checks. *Acceptance: registering a
bench with training-set leakage fails CI.*

**Phase B2.5 — Plane split & model registry (1–2 sprints, prerequisite for B3/B4)**
Registry bucket + manifest schema (§6.3); `model_steward` on the serving plane (deploy/
rollback mechanics moved out of the Makefile training context); `08_rsi_loop.py` ends at
publish; `nexus.models.promote/promoted/rejected` subjects + NATS per-plane authorization;
deployment_prep ships baseline weights as registry v0; contract suite (§6.8).
*Acceptance: a manifest with a missing gate or bad SHA-384 is refused by the steward;
serving boots from local cache with the registry down; promotion and re-pin rollback both
recorded in the RSI ledger.*

**Phase B3 — Fail-fast learning (2 sprints, needs B2.5 + production traffic)**
Shadow champion/challenger (challenger = second registry version in a second adapter slot);
miss-driven micro-batch path with full gate reuse; failure-clustering gap reports;
time-to-learn KPI on the ledger. *Acceptance: a seeded synthetic miss travels
adjudication → replay case → micro-batch → gated promotion in <72h in the lab.*

**Phase B4 — Live rollback + config matrix (1 sprint, needs B2.5)**
24h post-deploy control bands + auto re-pin rollback via the steward; quantization ×
fine-tune matrix for Model A ONNX and any quantized variant; baseline-ladder quarterly
run. *Acceptance: injected metric degradation in the lab triggers re-pin without human
action.*

Proposed backlog IDs (to be added to `planning_docs/BACKLOG.md` §1.2/§5 when implementation
starts): **M-26** runner+registry, **M-27** investigation metrics + outcome join, **M-28**
replay bench, **M-29** tier-0 canary in RSI loop, **M-30** shadow champion/challenger,
**M-31** micro-batch miss path, **M-32** live-metric rollback, **M-33** model registry +
manifest contract, **M-34** model_steward serving agent (deploy logic relocated),
**Q-19** bench CI section, **Q-20** leakage/judge-calibration gates, **Q-21** registry/
promotion contract tests. M-25 is absorbed by M-26.

---

## 8. KPIs — how we know the program itself works

| KPI | Baseline (today) | Target after B4 |
|---|---|---|
| Time-to-learn (miss → deployed fix) | unmeasured (~weeks) | <72h (micro-batch path), measured |
| Operator agreement | unmeasured | measured + trending up across 3 cycles |
| FP burden per analyst-day | unmeasured | measured, −30% from first 30-day baseline |
| Doomed-checkpoint cost | full gate suite per attempt | tier-0 catches ≥80% of eventual gate failures in ≤5 min |
| Benchmark trust | none (no leakage/judge checks) | 0 leaked cases; judge κ ≥ 0.6 |
| Regression-gate coverage | vacuous (no scores file) | every deploy gated on ≥6 capability axes |
| Weight provenance | symlink swap from training context | every served weight traceable to a signed registry manifest + gate scores |
| Detection latency under training | shared GPUs, unmeasured | MTTV stable (±10%) during training windows |

---

## 9. Risks & guardrails

* **Goodhart on embedded metrics** — agreement rate can be gamed by timid verdicts. Always
  pair: agreement *and* miss proxy; FP burden *and* recall on replay misses. The regression
  gate evaluates the vector, not a single scalar.
* **Replay label noise** — operator adjudications are imperfect; replay cases carry a
  `label_confidence` and disputed cases need two adjudications before entering tier-0.
* **Shadow-mode leakage into memory** — challenger paths must be hard-blocked from RAG
  writes, SOAR, and the immunity path (same pattern as the canary tripwire: assert in code,
  test in lab_agentic_swarm).
* **Registry seam drift** — the plane split adds the one thing P13 proved dangerous: a new
  cross-layer contract. Mitigation is structural: the §6.8 contract suite ships *with* the
  seam (manifest schema, NATS subjects + per-plane authorization, refuse-on-unverifiable,
  boot-with-registry-down), not after it.
* **Air-gap discipline** — all external benchmark data via `data/ti_feeds/` mirrors;
  `09_benchmark_runner.py` runs with `TRANSFORMERS_OFFLINE=1` like every RSI subprocess;
  the registry lives on the internal MinIO — promotion never crosses the enclave boundary.
* **Privacy/sovereignty** — replay cases contain real telemetry; they live under the same
  storage controls as cold storage and never enter any externally-shared artifact.
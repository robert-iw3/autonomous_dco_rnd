# Sentinel Nexus -- Sovereign MLOps Pipeline

## Overview

The MLOps pipeline trains, evaluates, and deploys the four-model AI swarm that powers Sentinel Nexus. All training runs air-gapped on the analytics node; no model weights or training data leave the sovereign environment. The pipeline is fully orchestrated via `Makefile` and triggered from the GitLab CI/CD stage `06-trigger-mlops.sh`.

---

## Architecture: Training Source Coverage

The pipeline now produces training data across **12 source types** covering all telemetry sources the swarm ingests in production:

| Source Type | Vector Space | Expert Agent | Data Captured |
|---|---|---|---|
| `sysmon_sensor` | `windows_math` **(6D)** | `host_expert` | Windows Sysmon events: +grant_access_score (EventID 10), +driver_trust_score (EventID 6/7): process, registry, network, pipe, DNS, DLL load |
| `windows_deepsensor` | `deepsensor_math` **(4D)** | `host_expert` | Windows DeepXDR EdrRow: score, avg_entropy, max_velocity, event_count |
| `linux_sentinel` | `sentinel_math` (5D) | `host_expert` | Linux eBPF/auditd: comm, command_line, uid, entropy |
| `aws_cloudtrail` | `cloud_flow` (5D) | `cloud_expert` | IAM actions, API velocity, role assumption chains |
| `aws_guardduty` | `cloud_flow` (5D) | `cloud_expert` | Pre-scored findings: Tor, credential exfil, C2 |
| `azure_activity` | `cloud_flow` (5D) | `cloud_expert` | Resource lifecycle, RunCommand, RBAC changes |
| `azure_entraid` | `cloud_flow` (5D) | `cloud_expert` | Impossible travel, MFA bypass, SPN credential abuse |
| `gcp_audit` | `cloud_flow` (5D) | `cloud_expert` | SA key export, privilege escalation, API enumeration |
| `gcp_scc` | `cloud_flow` (5D) | `cloud_expert` | Pre-triaged SCC findings: cryptomining, IAM misconfig |
| `vmware_syslog` | `cloud_flow` (5D) | `cloud_expert` | ESXi SSH, vCenter snapshot abuse, NSX lateral movement |
| `network_tap` | `network_tap` (8D) | `nettap_expert` | 42-field L7 sessions: JA3, DNS tunneling, exfil ratio |
| `suricata_eve` | `c2_math` (8D) | `net_expert` | IDS alerts: JA3, ET rules, port scan, file hash |

---

## Data Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       STAGE 0: DATA PREPARATION                          │
│                                                                          │
│  generate_golden_datasets.py                                             │
│  ├── Track 1: spatial_telemetry_train.jsonl   (200 records, 10 sources)  │
│  │           spatial_tensors_v1.safetensors   (tensor registry)          │
│  ├── Track 2: network_adversarial_v1.jsonl    (36 C2 profiles)           │
│  ├── Track 3: rlhf_preferences_v1.jsonl       (TP + TN + HN + Cloud)     │
│  └── Hard-Neg: hard_negatives_sft_v1.jsonl   (21 CoT-format records)     │
│                                                                          │
│  01_spool_datasets.py --target all                                       │
│  ├── Track 1: live Qdrant vectors (c2_math, sentinel_math, windows_math, │
│  │            cloud_flow, network_tap)                                   │
│  ├── Track 2: S3 C2 sensor data (linux_c2, windows_c2)                   │
│  ├── Track 3: SOAR decision log (Redis/NATS golden dataset)              │
│  ├── Track 4: network_tap Hive-partitioned Parquet (42 fields)           │
│  ├── Track 5: RLHF operator dismissals → hard_negatives_operator_v1      │
│  ├── Track 6: TTP behavioral S3 match (all *_query_index.json patterns)  │
│  ├── Track 7: sysmon_sensor Parquet → sysmon_sft_v1.jsonl                │
│  └── Track 8: Firecracker sandbox verdicts → ground-truth TP/TN pairs    │
│              Written by 06_sandbox_runner.py; consumed as reward signal  │
│              for PPO loop + DPO hard negatives (SKELETON -- Phase 1)     │
│                                                                          │
│  stage_*_behavioral.py  (12 TTP corpora -- offline, no S3 required)      │
│  ├── recon_behavioral_v1.jsonl              (1_Recon,  24 cls, 288 recs) │
│  ├── persistence_behavioral_v1.jsonl        (2_Pers,   30 cls, 360 recs) │
│  ├── c2_behavioral_v1.jsonl                 (3_C2,     31 cls, 372 recs) │
│  ├── bypass_behavioral_v1.jsonl             (4_Bypass, 33 cls, 396 recs) │
│  ├── lateral_movement_behavioral_v1.jsonl   (5_LM,     28 cls, 336 recs) │
│  ├── exfiltration_behavioral_v1.jsonl       (7_Exfil,  21 cls, 252 recs) │
│  ├── active_directory_behavioral_v1.jsonl   (AD,       20 cls, 240 recs) │
│  ├── malware_behavioral_v1.jsonl            (6_Mal,    14 cls, 168 recs) │
│  ├── linux_exploitation_behavioral_v1.jsonl (LinExpl,  13 cls, 156 recs) │
│  ├── lotl_behavioral_v1.jsonl               (LOTL,     24 cls, 288 recs) │
│  ├── windows_exploitation_behavioral_v1.jsonl (WinExp, 22 cls, 264 recs) │
│  └── cross_source_temporal_v1.jsonl         (XSrc,      5 cls,  60 recs) │
│      Total TTP corpus: 265 active classes, 3,180 SFT records             │
│      Sensors: sysmon_sensor, windows_deepsensor, network_tap,            │
│               linux_sentinel, azure_entraid, aws_cloudtrail, macos_sensor│
│                                                                          │
│  05_synthetic_data_gen.py --count 100    (optional, requires API key)    │
│  └── synthetic_hard_negatives_v1.jsonl  (Claude-generated, validated)    │
└──────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       STAGE 1: MODEL A (BASELINE)                       │
│                                                                         │
│  build_baseline_windows.py                                              │
│  └── DuckDB → sliding windows [N x 64 x 8] → baseline_train_windows     │
│                                                                         │
│  train_lstm_ae.py                                                       │
│  ├── BiLSTM-AE encoder BiLSTM(8→64)→Linear(128→32)                      │
│  ├── Decoder BiLSTM(32→64)→Linear(128→8)                                │
│  ├── Threshold calibration: μ + 3σ on validation set                    │
│  └── Exports: model weights + normalization + SHA-384 manifest          │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    STAGE 2a: MODEL C -- CoT SFT                             │
│                                                                             │
│  02_train_sft_cot.py                                                        │
│  ├── Sources: spatial_telemetry_train + hard_negatives_sft + operator_hn    │
│  │            + 9x TTP behavioral staging + sysmon_sft_v1 (Track 7)         │
│  ├── DataCollatorForCompletionOnlyLM                                        │
│  │   └── Mask: system prompt + user telemetry (no loss)                     │
│  │   └── Loss: <analysis>3-axis CoT</analysis> + verdict token              │
│  ├── QLoRA 4-bit NF4, LoRA r=16/α=32, all projection layers                 │
│  └── Saves: nexus_spatial_lora_cot_final/ + projector SHA-384               │
│                                                                             │
│                    STAGE 2b: MODEL C -- QLoRA + PROJECTOR                   │
│                                                                             │
│  02_train_qlora.py                                                          │
│  ├── NexusMultimodalTrainer: splices sensor vectors at <|spatial_vector|>   │
│  ├── Explicit vector_name routing → correct SpatialProjector head           │
│  │   c2_math(8D), sentinel_math(5D), windows_math(6D),                      │
│  │   deepsensor_math(4D), trellix_math(4D), cloud_flow(5D), network_tap(8D) |
│  ├── Per-head gradient tracking + early stopping (patience=3)               │
│  ├── --rlhf-mode ppo → run_ppo_loop() via trl.PPOTrainer (M-8 SKELETON)     │
│  │   Reward priority: sandbox verdict > SOAR outcome > operator label       │
│  │   Checkpoint every PPO_CHECKPOINT_INTERVAL (default 500) samples         │
│  │   Guard: checkpoint must pass eval-garak + eval-pyrit before swap        │
│  └── Saves: nexus_spatial_lora_final/ + spatial_projector.safetensors       │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 2c: MODEL B -- NETWORK ADVERSARIAL             │
│                                                                         │
│  02_train_network.py                                                    │
│  ├── Mistral-Small-3.1-24B, QLoRA 4-bit NF4                             │
│  ├── Track 2 curriculum: C2 beacon/exfil/DGA classification             │
│  ├── Track 4 curriculum: 42-field L7 session forensic analysis          │
│  ├── Dual early-stopping gates: T2 ≥98%, T4 ≥95% accuracy               │
│  └── DeepSpeed ZeRO-3 (multi-GPU): config/deepspeed_zero3.json          │
│      Shards params+grads+optimizer → fits 24B on dual A100 80GB         │
│      Invoke via: deepspeed 02_train_network.py --deepspeed              │
│                  config/deepspeed_zero3.json  (make train-network-zero3)│
│      Fallback:   config/deepspeed_zero2.json  (make train-network-zero2)│
│      Single-GPU: python3 02_train_network.py  (make train-network)      │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   STAGE 2d: MODEL D -- DPO CRITIC ALIGNMENT             │
│                                                                         │
│  02_train_dpo_critic.py                                                 │
│  ├── Gemma-3-4B, DPO/IPO (IPO more stable for ternary decision space)   │
│  ├── Category 1: Critical infra → MANUAL_REVIEW (DC, CA, DB servers)    │
│  ├── Category 2: Low-value workstation → CONFIRM_QUARANTINE             │
│  ├── Category 3: Model A baseline anomalies (corroborated vs marginal)  │
│  ├── Category 4: Hard negatives -- TP look-alikes → DISMISS             │
│  │   Windows: certutil -hashfile, PS-enc from SCCM, BITS, nc -z ...     │
│  │   Linux: crontab -l, wget packages.microsoft.com, curl GitHub API ...│
│  │   Cloud: Lambda@Edge AssumeRole, Veeam snapshots, Cloud Build keys,  │
│  │          Azure B2B federation, Zabbix beacon ...                     │
│  └── compute_reward_score(): F1-calibrated asymmetric reward table      │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   STAGE 2e: REWARD MODEL                                │
│                                                                         │
│  04_reward_model.py --mode train                                        │
│  ├── Bradley-Terry reward model (AutoModelForSequenceClassification)    │
│  ├── Trained on rlhf_preferences_v1.jsonl (all 5 categories)            │
│  ├── Reward asymmetry: FN=-0.75, FP=-1.00, TP=+1.00, TN=+0.50           │
│  └── Saves: nexus_reward_model_final/                                   │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       STAGE 3: EVALUATION GATES                          │
│                                                                          │
│  03_eval_model.py         (Model C -- must pass all 5 checks ≥99%)       │
│  ├── OS hallucination: no Linux artifacts in Windows context             │
│  ├── Schema adherence: RECOMMENDED_ACTION must be contain|monitor|dismiss│
│  ├── Prompt injection immunity: <untrusted_payload> bypass attempts      │
│  ├── Spatial math boundary: sub-threshold (0.84) must NOT contain        │
│  └── Cross-vector contamination: no field leakage across vector spaces   │
│                                                                          │
│  03_eval_network.py       (Model B -- dual independent gates)            │
│  ├── Track 2 gate: ≥98% TTP mapping accuracy on C2 beacons               │
│  └── Track 4 gate: ≥95% forensic quality on L7 session analysis          │
│                                                                          │
│  03_eval_critic.py        (Model D -- 4-phase evaluation suite)          │
│  ├── Phase 1: DPO alignment (CONFIRM/DISMISS/MANUAL_REVIEW determinism)  │
│  ├── Phase 2: Disruption governance (DisruptionIndex cost function)      │
│  ├── Phase 3: Precision/recall/F1 per cohort (TP/TN/hard_negative)       │
│  │   └── Hard-neg precision < 0.5 → deployment HALTED                    │
│  └── Phase 4: Stratified 5-fold cross-validation (F1 variance ≤0.15)     │
│                                                                          │
│  04_reward_model.py --mode judge  (LLM-as-Judge ensemble)                │
│  ├── Loads critic_judge_eval.jsonl (exported by Phase 3)                 │
│  ├── Routes each verdict through llm_providers failover chain            │
│  ├── Ensemble score: 40% rule-based + 60% LLM judge                      │
│  └── Publishes scores → nexus.training.rlhf.judge_scores (NATS)          │
└──────────────────────────────────────────────────────────────────────────┘
                              │ All gates passed
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       STAGE 4: WEIGHT MERGE + DEPLOY                    │
│                                                                         │
│  04_merge_weights.py                                                    │
│  └── Fuses LoRA adapters → OUTPUT_DIR (timestamped)                     │
│                                                                         │
│  make deploy                                                            │
│  ├── Atomic symlink swap (nexus_spatial_production → new weights)       │
│  ├── SHA-384 full-directory integrity manifest (ATLAS AML.T0044)        │
│  ├── vllm-inference.service restart                                     │
│  └── Readiness probe polling (12 x 10s); auto-rollback on failure       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Makefile Targets

```bash
make data-all           # Generate golden datasets + spool all tracks (S3/Qdrant + all TTP corpora)
make data-hardneg       # Track 5 only: spool operator-dismissed incidents from RLHF archive

# ── TTP Behavioral Corpus Targets ──────────────────────────────────────────────
# stage-* : generate synthetic SFT records only (no S3 required, runs offline)
# data-*  : stage-* + spool live S3-matched behavioral evidence (Track 6)
# Track 6 auto-discovers all *_query_index.json -- new stages are picked up automatically
make stage-recon        # 1_Recon:              20 tool classes, 240 records
make stage-persistence  # 2_Persistence:        27 tool classes, 312 records
make stage-c2           # 3_C2:                 27 tool classes, 312 records
make stage-bypass       # 4_Bypass_Detection:   31 tool classes, 336 records
make stage-lateral      # 5_Lateral_Movement:   24 tool classes, 288 records
make stage-malware      # 6_Malware_Tradecraft: 11 tool classes, 132 records
make stage-exfil        # 7_Exfiltration:       20 tool classes, 240 records
make stage-ad           # Active-Directory:     20 tool classes, 240 records
make stage-tools        # tools/ supplemental:  15 tool classes, 180 records
                        # Total (all stage-*):  175 tool classes, 2,100 SFT records

make data-recon         # stage-recon + Track 6 S3 match
make data-persistence   # stage-persistence + Track 6 S3 match
make data-c2            # stage-c2 + Track 6 S3 match
make data-bypass        # stage-bypass + Track 6 S3 match
make data-lateral       # stage-lateral + Track 6 S3 match
make data-malware       # stage-malware + Track 6 S3 match
make data-exfil         # stage-exfil + Track 6 S3 match
make data-ad            # stage-ad + Track 6 S3 match
make data-tools         # stage-tools + Track 6 S3 match

make data-sysmon        # Track 7: spool live sysmon_sensor Parquet from S3 cold storage

# ── Model Training ─────────────────────────────────────────────────────────────
make train-all             # Full sequence: baseline → sft-cot → spatial → network-zero3 → critic → reward
make train-baseline        # Model A: BiLSTM-AE
make train-sft-cot         # Model C CoT SFT (golden + hard negatives + ALL 6 TTP corpora + sysmon live)
make train-spatial         # Model C QLoRA + SpatialProjector
make train-network-zero3   # Model B DeepSpeed ZeRO-3 (PREFERRED — multi-GPU, 24B)
make train-network-zero2   # Model B DeepSpeed ZeRO-2 (fallback — multi-GPU)
make train-network         # Model B single-GPU path (no DeepSpeed)
make train-critic          # Model D DPO/IPO with hard negatives
make train-reward          # Bradley-Terry reward model

make eval-spatial       # Model C: hallucination + schema + injection + spatial math
make eval-network       # Model B: dual-gate TTP accuracy
make eval-critic        # Model D: Phase 1 + 2 only (fast)
make eval-critic-full   # Model D: Phase 1–4 + LLM-as-judge (full suite)

make generate-synthetic # Claude API synthetic hard negative generation (requires ANTHROPIC_API_KEY)

make deploy             # Atomic weight swap + readiness probe + auto-rollback
make all                # End-to-end: data-all → train-all → eval-critic-full → deploy

# ── Phase 1: Continuous Threat Feed + Sandbox (SKELETON -- requires local ti_feeds mirrors) ──
make feed-ingest        # 07_feed_ingest.py: Atomic Red Team 4-stage filter → sandbox queue
                        # + Track 6 threat_feed_query_index.json + threat_feed_sft_v1.jsonl
make kill-chains        # 07_feed_ingest.py --mode kill-chains: CISA advisories → kill_chain_sft_v1.jsonl
make sigma-validate     # 07_feed_ingest.py --mode sigma-validate: Sigma ↔ Track 6 gap analysis
make sandbox-run        # 06_sandbox_runner.py: execute queued atomics in Firecracker micro-VMs
                        # Output: mlops/data/sandbox/results_v1.jsonl (Track 8 ground truth)

# ── Phase 2: Adversarial Gate + Generator/Critic Loop (SKELETON) ──────────────────────────
make eval-garak         # 03_eval_model.py --mode garak: jailbreak/xss/inject scan
                        # Config: mlops/config/garak_config.yaml; blocks deploy on any success
make eval-pyrit         # 03_eval_model.py --mode pyrit: multi-turn attack orchestrator
make critic-loop        # 05_critic_loop.py: Generator → NeMo schema check → Critic → retry/promote
                        # Output: sandbox_queue_v1.jsonl (reward ≥ 0.95) + hard_negatives_sft_v1.jsonl
make train-ppo          # 02_train_qlora.py --rlhf-mode ppo: online RLHF on sandbox verdicts

# ── Phase 3: NeMo Guardrails (SKELETON -- requires nemoguardrails>=0.5.0) ──────────────────
make guardrails-validate # Lint mlops/config/nemo_guardrails/config.yaml against remediation_schema.json

# ── Pipeline Validation (run before training to catch schema drift) ─────────
python scripts/validate_pipeline.py                  # Schema-only (uses existing JSONL)
python scripts/validate_pipeline.py --smoke-records 2 # Full smoke run (re-runs all 9 TTP corpora)
# 22-check suite (34 with smoke run):
#   - Python syntax: 35 scripts
#   - JSONL schema: 9 corpus files, 2,100 records (fields, message format, spatial token)
#   - Query indices: 9 *_query_index.json files (consumed by Track 6)
#   - Model configs: corpus_config.toml, model_config.toml
#   - Container files: 4 Podman Quadlets ([Container] section, env keys)
#   - Spatial token coverage: <|spatial_vector|> in every user message
#   - Vector name coverage: all 8 known spaces (windows_math 6D, deepsensor_math 4D, trellix_math 4D, sentinel_math 5D, c2_math 8D, cloud_flow 5D, network_tap 8D, embedding_384 384D)
#   - Spool script Track 6 auto-discovery validation
#   - Makefile target completeness (all 12 stage scripts referenced)
```

---

## Dataset Schema Reference

### `spatial_telemetry_train.jsonl` (Track 1)
Feeds Models C SFT and CoT SFT. Schema:
```json
{
  "event_id": "uuid",
  "timestamp": 1234567890.0,
  "vector_name": "windows_math | sentinel_math | cloud_flow | network_tap | c2_math",
  "source_type": "windows_deepsensor | linux_sentinel | aws_cloudtrail | ...",
  "classification": "true_positive | false_positive",
  "messages": [
    {"role": "system",    "content": "<expert agent persona for this source_type>"},
    {"role": "user",      "content": "Spatial Anomaly Detected. Source: ...\nVector: <|spatial_vector|>\nRaw Payload: {...}"},
    {"role": "assistant", "content": "TRUE/FALSE POSITIVE. ...\nRECOMMENDED_ACTION: contain|monitor|dismiss"}
  ]
}
```

### `hard_negatives_sft_v1.jsonl`
Same schema as Track 1, but assistant content is CoT-formatted:
```json
{
  "messages": [
    {"role": "assistant", "content": "<analysis>\n[AXIS 1]...\n[AXIS 2]...\n[AXIS 3]...\n[CONCLUSION]\n</analysis>\nFALSE POSITIVE. ...\nRECOMMENDED_ACTION: dismiss"}
  ]
}
```

### `rlhf_preferences_v1.jsonl` (Track 3 / DPO)
Feeds Model D DPO/IPO training. Schema:
```json
{
  "prompt": "Evaluate containment action for Incident X. Context: ... Swarm Action: isolate_host.\nGovernance Context: ...",
  "chosen": "CONFIRM_QUARANTINE | DISMISS_FALSE_POSITIVE | MANUAL_REVIEW",
  "rejected": "CONFIRM_QUARANTINE | DISMISS_FALSE_POSITIVE | MANUAL_REVIEW",
  "category": "true_positive | true_negative | hard_negative | cloud_true_positive | cloud_true_negative"
}
```

---

## RLHF Feedback Loop

```
Live Investigation
      │
      ▼
operator_action = CONFIRM_QUARANTINE
                | DISMISS_FALSE_POSITIVE   ──── if swarm said TP: Track 5 (hard negative)
                | MANUAL_REVIEW
      │
      ▼
worker_rlhf (Rust) ────────► NATS nexus.training.rlhf
      │                             │
      │   circuit breaker:          ▼
      │   global >50 overrides  01_spool_datasets.py --target critic
      │   per-op  >10 overrides  └── mines DISMISS_FALSE_POSITIVE feedback
      │                              where swarm_verdict = true_positive
      ▼                                        │
TrainingRecord published                       ▼
to nexus.training.rlhf.records        hard_negatives_operator_v1.jsonl
                                               │
                    ┌──────────────────────────┤
                    ▼                          ▼
             02_train_dpo_critic.py   02_train_sft_cot.py
                    │                          │
                    └──────────┬───────────────┘
                               ▼
                    04_reward_model.py --mode judge
                               │
                               ▼ publishes ensemble scores
                    nexus.training.rlhf.judge_scores
```

---

## Vector Space Routing

The `vector_name` field on every training record determines which `SpatialProjector` head receives gradients during Model C training, and which expert receives the vector at inference time.

| `vector_name` | Dimension | Source Types | Expert |
|---|---|---|---|
| `c2_math` | 8D | `linux_c2`, `windows_c2`, `suricata_eve` | `net_expert` |
| `sentinel_math` | 5D | `linux_sentinel` | `host_expert` |
| `windows_math` | **6D** | `sysmon_sensor` | `host_expert` |
| `deepsensor_math` | **4D** | `windows_deepsensor` | `host_expert` |
| `trellix_math` | **4D** | `trellix_ens` | `host_expert` |
| `cloud_flow` | 5D | `aws_*`, `azure_*`, `gcp_*`, `vmware_syslog` | `cloud_expert` |
| `network_tap` | 8D | `network_tap` | `nettap_expert` |
| `embedding_384` | 384D | golden dataset proxy | fallback |

**Important:** The `SOURCE_VECTOR_MAP` dict in `generate_golden_datasets.py` is the single source of truth for this routing. It must stay in sync with `nexus.toml → [nexus.named_vectors]` and `projector.py → VECTOR_DIMS`.

---

## Hard Negative Coverage Matrix

Hard negatives are the most important training examples for FP reduction. Every hard negative must have at least one surface TP feature and at least one unambiguous discriminative factor.

| Scenario | Surface TP Feature | Discriminative Factor |
|---|---|---|
| `certutil.exe -hashfile` | certutil LOLBIN | `-hashfile` (no download), no network |
| `powershell -enc` (SCCM) | base64 obfuscation | decoded = PSWindowsUpdate, parent = CcmExec |
| `svchost BITS → Akamai` | svchost external IP | `-s BITS` tag, known CDN range |
| `nc -zv` | netcat | `-z` zero-I/O mode |
| `crontab -l` | crontab access | `-l` is list, not `-e` |
| `wget packages.microsoft.com` | wget external download | Microsoft package repo URL, apt parent |
| `python3 http.server` | python3 spawning server | bind to local, no external connection |
| `curl api.github.com` | curl to external IP | CI/CD SA, GitHub API URL, release check |
| Lambda@Edge AssumeRole x45 | high-frequency AssumeRole | all IPs = CloudFront edge ranges |
| Azure B2B federation | impossible travel alert | SAML from trusted partner tenant |
| Veeam VM snapshots | rapid snapshot creation | VeeamSvcAccount, 02:00 window |
| Cloud Build SA key | iam:CreateAccessKey | Cloud Build infra IP, 1h TTL |
| Zabbix heartbeat | low-jitter 60s TCP | port 10051, is_internal_dst=True |
| Azure onboarding SP | roleAssignments/write | HR ticket flow, scoped permissions |
| CDN high-entropy DNS | entropy above DGA threshold | AS13335, DigiCert cert, 0% NXDOMAIN |

---

## Future Roadmap

### Phase 4 Performance Enhancements (P11 — complete)

- [x] **P4-A: Lance Arrow dataset format** — `write_lance_dataset()` in `corpus_utils.py`
  (pyarrow columnar, memory-mapped, graceful fallback when `pylance` absent).
  All 11 `stage_*_behavioral.py` scripts accept `--output-lance`. `02_train_sft_cot.py`
  prefers `.lance` files via `_load_ttp_dataset()` / `TTP_LANCE_SOURCES`. `corpus_config.toml`
  has dual `*_staging` / `*_lance` entries. Expected gain: 4–10x faster I/O on epoch 2+.

- [x] **P4-C: DeepSpeed ZeRO-3 for Model B** — `config/deepspeed_zero3.json` (stage=3,
  contiguous_gradients, 5e8 allgather/reduce buckets). `02_train_network.py` accepts
  `--deepspeed` arg; `train-all` calls `train-network-zero3` (deepspeed launcher + ZeRO-3
  config). ZeRO-2 fallback retained in `config/deepspeed_zero2.json`. ZeRO-3 shards
  parameters + gradients + optimizer states — required for 24B on dual A100 80GB without OOM.

- [x] **P4-D: Qdrant gRPC for Track 1 scroll** — `01_spool_datasets.py` uses
  `QdrantClient(host=QDRANT_HOST, port=QDRANT_GRPC_PORT, prefer_grpc=True)` (default port
  6334). Env-configurable (`QDRANT_HOST`, `QDRANT_GRPC_PORT`). 2–3x faster than REST for
  batch scrolls on large corpora. `Dockerfile.mlops` needs `qdrant-client[grpc]` extra for
  production gRPC.

### Completed (this cycle)

- [x] **TTP behavioral corpus (12 phases, 263 active classes, 3,156 records)** -- Twelve MITRE ATT&CK tactic phases with behavioral-only detection. Covers Recon, Persistence, C2, Bypass/Evasion, Lateral Movement, Malware, Exfiltration, AD, Windows Exploitation, Linux Exploitation, LOTL, and Cross-Source Temporal. `stage_tools_supplemental.py` retired -- all 25 classes migrated to correct category scripts.
- [x] **Microsoft tooling corpus expansion** -- 10 new classes from `arcanaeum/offsec/ttps/tools/microsoft/` + CVE-2026-41096 DLL proxy hijack, placed directly in category scripts. Query alignment validated via `tests/test_s3_query_alignment.py`.
- [x] **Sensor expansion** -- `lateral_movement`, `recon`, `persistence` scripts gained `azure_entraid` + `linux_sentinel`. All 12 scripts pass 10/10 alignment tests.
- [x] **Staging path consolidation** -- Authoritative path: `mlops/data/staging/`. Stale `project_empros/data/staging/` removed. `STAGING_DIR` corrected in `tests/test_s3_query_alignment.py` and `tests/mlops_eval_minilab/eval_config.py`.
- [x] **Track 6 auto-discovery** -- `01_spool_datasets.py` discovers all `*_query_index.json` files at runtime; new stages are picked up without spooler changes.
- [x] **Internal sovereign TI (OpenCTI)** -- Air-gapped OpenCTI 6.8 on `ti` tier (10.0.90.x), MITRE ATT&CK pre-loaded, `OpenCTIProvider` in `ti_lookup.py` for zero-egress enrichment.
- [x] **Pipeline validator** -- `validate_pipeline.py` (34 checks): syntax, schema, spatial token, vector names, indices, configs, containers.
- [x] **ADDON-Ph2: PyRIT evaluator** -- `03_eval_pyrit.py` (5 scenarios, rule-based FAIL gate, hard-negative logging, 56 tests). See Phase 2 for full details.
- [x] **ADDON-Ph3: Cross-source temporal expansion + corpus_utils alias sync** -- `cross_source_temporal.py` and `stage_cross_source_temporal.py` extended to 5 classes (60 records). `mlops/corpus_templates/corpus_utils.py` synced with `SENSOR_FIELD_ALIASES` + `_apply_aliases()` from mlops/scripts mirror; `fmt_edr()` now accepts live sensor Parquet field names (`path`→`Image`, `command_line`→`CommandLine`). 57 offline tests (`test_cross_source_temporal.py`, 0.08s).
- [x] **ADDON-Ph4: RSI closed-loop orchestrator + Skill Library** -- `08_rsi_loop.py` + `skills_v1.jsonl` + all safety invariants (air-gap, NATS quorum, alignment gate, Ansible Vault). 49 offline tests (`test_rsi_loop.py`, 0.06s). See Phase 4 for full details.
- [x] **PERF-Ph1: Training acceleration + ONNX export** -- Unsloth graceful-fallback added to `02_train_qlora.py` and `02_train_sft_cot.py` (FastLanguageModel path with smarter gradient checkpointing; degrades to standard BnB QLoRA if unsloth absent; guard prevents double `resize_token_embeddings` call). `mlops/scripts/export_model_a_onnx.py`: ONNX opset-17 export for BiLSTM-AE with fused z-score normalization (`NormalizedAE` wrapper), dynamic batch/seq axes, numerical equivalence check (max delta < 1e-4), SHA-384 manifest append. `mlops/Makefile`: `export-onnx` target. `planning_docs/PERFORMANCE_ENHANCEMENT_PLAN.md`: full 14-option decision matrix with phased implementation plan (Phases 1–5).
- [x] **PERF-TI: Threat Intelligence RAG service** -- `services/worker_ti_ingest/` new FastAPI Python service (port 8010). Hybrid retrieval: TurboVec IdMapIndex SIMD ANN (numpy brute-force fallback) + BM25Okapi keyword index. Embeddings: BAAI/bge-m3 1024D via sentence-transformers (TRANSFORMERS_OFFLINE=1). Reranker: CrossEncoder ms-marco-MiniLM-L-6-v2 (top-20→top-5, ~45ms CPU). Hybrid score: α=0.65 dense + (1-α)xBM25_normalized. Qdrant `nexus_ti_corpus` collection (ScalarQuantization INT8, named vector `ti_embed`). NATS publish to `nexus.ti.status` for progress events. Document parsers: PDF (PyMuPDF), STIX 2.x bundle, Sigma YAML, JSONL, IOC CSV (sliding window 400 tokens, 40 overlap). Endpoints: POST /ingest, GET /status/{job_id}, GET /corpus, DELETE /document/{doc_id}, POST /retrieve, GET /health. Dockerfile air-gap ready.
- [x] **PERF-LG: Looking Glass TI Intelligence tab (7th view)** -- `services/looking_glass/src/routes/api/ti/+server.ts`: SvelteKit server endpoints proxying to worker_ti_ingest + SSE relay from `nexus.ti.status`. `stores.ts` extended with TIDocument, TICorpusStats, TIUploadEvent types and tiDocuments/tiStats/tiUploadLog/appendTIUploadEvent/refreshTICorpus. `+page.svelte`: drag-and-drop upload dropzone, SSE activity log, corpus stats cards, document browser table with retract buttons; `{ id: 'ti', label: 'TI Intelligence', icon: '◎' }` added to nav.
- [x] **PERF-TV: TurboVec MLOps integrations** -- `mlops/scripts/corpus_utils.py`: TurboVecNgramIndex (char 2–4-gram hash → L2-normalised float32 vector, dim=256, TurboVec ANN + numpy brute-force fallback), TurboVecDeduplicator (threshold 0.92, check_and_add), HardNegativeMiner (cross-class contrastive DPO pair mining), SkillDeduplicator (dim=256, threshold 0.90, load_from_library). Three script integrations: (1) `01_spool_datasets.py` Track-6 dedup via `--dedup-threshold` (default 0.92); (2) `05_critic_loop.py` hard-negative mining: `_append_mined_negatives` writes `source='turbovec_hn_mining'` DPO pairs to `hard_negatives_sft_v1.jsonl`; (3) `08_rsi_loop.py` `promote_skill` near-dup guard via process-lifetime SkillDeduplicator singleton (warm from library file, updated on every successful promotion). 58/58 offline tests (`tests/test_turbovec_mlops.py`, 0.14s). Bug fix: `_get_skill_deduplicator` bumped from dim=64 to dim=256 to distinguish skills with same JSON schema structure.

---

### Phase 1 -- Foundation: Sandbox, Telemetry, and Continuous Threat Feed (SKELETON COMPLETE)

Core infrastructure for continuous learning. No model architecture changes -- purely data and infra.

- [x] **Firecracker micro-VM sandbox farm** (`mlops/scripts/06_sandbox_runner.py` -- SKELETON) -- Reads queue entries from `mlops/data/sandbox/queue/`; substitutes `#{arg}` placeholders; launches Firecracker with `--no-api --config-file`; parses `NEXUS_SYSMON:` / `NEXUS_NETTAP:` / `NEXUS_AUDITD:` / `NEXUS_VERDICT:` tagged JSON from VM stdout; writes to `results_v1.jsonl`. Supports `--dry-run`. Requires Firecracker binary + base rootfs. Makefile: `make sandbox-run`. 13/13 tests.

- [x] **Threat feed pipeline** (`mlops/scripts/07_feed_ingest.py` -- SKELETON) -- Four-stage atomic filter over local Atomic Red Team mirrors (no external egress). Three modes: `feed` (4-stage filter → sandbox queue + Track 6 index + `threat_feed_sft_v1.jsonl`), `kill-chains` (CISA advisory STIX → `kill_chain_sft_v1.jsonl`), `sigma-validate` (Sigma ↔ Track 6 gap → `mlops/todos.md`). All feeds read from `data/ti_feeds/` local mirrors. Makefile: `make feed-ingest`, `make kill-chains`, `make sigma-validate`. 26/26 tests.

- [ ] **Cross-source temporal corpus expansion** -- Expanded from 3 → 5 classes/60 records (ADDON-Ph3 ✅): `LinuxBeaconAfterExec` (linux_sentinel exec from `/tmp/` + network_tap C2 beacon, T+20s) and `CloudLateralMovement` (azure_entraid impossible-travel + aws_cloudtrail IAM AttachUserPolicy, T+60s). Long-term target: ≥20 classes covering Azure VM RunCommand, GCP SA key export, and multi-cloud kill chains. Target: 240 SFT records.

- [ ] **Negative transfer defense** -- Add cross-vector contamination tests to `03_eval_critic.py`: TP recall on `azure_entraid` must not drop >2% after any cloud_flow hard negative batch.

- [ ] **eBPF + auditd telemetry pipes** -- Ingest raw Linux eBPF + auditd events into `01_spool_datasets.py` Track 7 extension from sandbox farm captures.

---

### Phase 2 -- Validation: LLM Red-Teaming CI Gate and Generator/Critic Loop (SKELETON COMPLETE)

All model variants must pass adversarial regression before production promotion.

- [x] **garak LLM scan gate** (`mlops/config/garak_config.yaml` -- SKELETON) -- Config: `probes: [jailbreak, xss, promptinject]`, all thresholds 0.0, `rollback_on_fail: true`. Wire into `03_eval_model.py --mode garak`. Failure logs to `logs/garak_failures/`; passed to Critic as zero-shot correction prompts. Makefile: `make eval-garak`. 10/10 config tests.

- [x] **PyRIT multi-turn attack orchestrator** (`mlops/scripts/03_eval_pyrit.py` -- ADDON-Ph2 ✅) -- 5 attack scenarios (malicious patch approval, eBPF suppression, NATS credential extraction, role confusion, schema injection). Rule-based `_evaluate_offline()` gate: unsafe token list + schema corruption + TP-suppression checks. Hard-negative logging to `logs/hard_negatives/`. Air-gapped: `PYRIT_OFFLINE=1`, `MODEL_URL` defaults to localhost Ollama. Makefile: `make eval-pyrit`. 56/56 offline tests.

- [x] **Generator/Critic agent loop** (`mlops/scripts/05_critic_loop.py` -- SKELETON) -- NeMo 3-field schema check → Critic score → retry with feedback (max `MAX_RETRIES=3`). Score ≥ `PROMOTE_THRESHOLD=0.95` → `sandbox_queue_v1.jsonl`. Below threshold → `hard_negatives_sft_v1.jsonl` as DPO negative pairs. Schema violations logged to `logs/schema_violations/`. Supports `--dry-run`. Makefile: `make critic-loop`. 18/18 unit tests.

- [x] **PPO online RLHF loop** (`02_train_qlora.py --rlhf-mode ppo` -- SKELETON) -- `run_ppo_loop()` with `trl.PPOTrainer`. Reward priority: sandbox verdict → SOAR outcome → operator label. Checkpoint every 500 samples; garak + PyRIT gate required before checkpoint promotion. Makefile: `make train-ppo`. 8/8 contract tests.

- [ ] **SOAR outcome label track (Track 8)** -- Pull post-containment outcomes from SOAR into `01_spool_datasets.py`. CONFIRM_QUARANTINE → re-infection within 24h = negative label. Requires production deployment.

---

### Phase 3 -- Guardrails: Runtime Hardening (CONFIG COMPLETE -- integration pending)

NeMo-Guardrails bounds every input and output channel before the execution engine sees it. Config directory: `mlops/config/nemo_guardrails/`.

- [x] **NeMo input guardrails** (`mlops/config/nemo_guardrails/input_rules.co` + `config.yaml`) -- Colang v1 rules blocking: `rm -rf`, `DROP TABLE`, prompt injection, role confusion, NATS redirect. `rails.input.flows: [check input safety, check nats redirect]`. Wire into `services/soar_adapter.py`, `services/slack_handler.py`, `services/nats_consumer.py`. Requires `nemoguardrails>=0.5.0`.

- [x] **NeMo output execution gate** (`mlops/config/nemo_guardrails/output_rules.co`) -- Blocks: `chmod`, `chown`, `usermod`, `useradd`, `systemctl disable/stop` on security daemons, `iptables -D`, `/etc/sudoers`, `/etc/passwd`. Allows: `iptables -A`, `NetworkPolicy`, `auditctl`, `CONFIRM_QUARANTINE`, `MANUAL_REVIEW`. `rails.output.flows: [check output safety, check service disruption]`.

- [x] **Schema enforcement** (`mlops/config/nemo_guardrails/remediation_schema.json`) -- JSON Schema draft-07, `additionalProperties: false`, 3 required fields: `target_component`, `remediation_script_base64` (base64), `verification_test_command`. `schema_enforcement.enabled: true`, `max_retries: 3`. Violations logged to `logs/schema_violations/` and appended to `hard_negatives_sft_v1.jsonl`. Makefile: `make guardrails-validate`.

- [x] **HashiCorp Vault credential client** (`mlops/scripts/vault_client.py` -- I-9 SKELETON) -- `VaultClient` wraps hvac KV v2: lazy connect, process-lifetime cache, `invalidate()`. `get_secret(path)` module-level singleton. Well-known paths: `nexus/nats/password`, `nexus/qdrant/api_key`, `nexus/models/hf_token`, `nexus/sensors/hmac_key`, `nexus/soar/webhook_secret`. Wire into `worker_soar`, `core_ingress`, `worker_qdrant`. Requires `hvac>=2.0.0` + `VAULT_ADDR`/`VAULT_TOKEN` via Ansible Vault.

- [ ] **Multi-cloud hard negatives from real tenants** -- `05_mine_cloud_fps.py`: query SOAR for cloud FP incidents → `hard_negatives_operator_v1.jsonl`. Target: ≥200 real cloud FPs. Requires production deployment.

---

### Phase 4 -- Autonomy: Closed-Loop Recursive Self-Improvement (Long-term)

Full RSI cycle: corpus auto-update → train → adversarial gate → conditional deploy, no human in the loop for routine weight updates.

- [ ] **Closed-loop corpus auto-update** -- `07_feed_ingest.py` sandbox results write directly to the correct `*_query_index.json` and re-run `make data-ttp` automatically when a new PoC verdict arrives. The pipeline detects the index update via filesystem watch and triggers `make train` without manual intervention.

- [ ] **Autonomous fine-tuning on sandbox scores** -- Sandbox validation scores (exploited / mitigated) become the primary reward signal replacing SOAR operator labels. `02_train_qlora.py` runs in continuous mode: small LoRA delta trained on each batch of ≥50 new sandbox verdicts, evaluated against garak + PyRIT gate, promoted if both pass. Failed promotions trigger Critic loop retuning.

- [x] **Tokenized Skill Library + RSI orchestrator** (`mlops/scripts/08_rsi_loop.py` -- ADDON-Ph4 ✅) -- Closed-loop RSI cycle: sandbox verdicts → `SkillEntry` schema validation (confidence ≥ 0.95, `sandbox_verdict` ∈ {mitigated|partial|failed}, 3 required remediation fields) → `promote_skill()` → `skills_v1.jsonl` → NATS `skill.update` hot-load. Safety invariants: `TRANSFORMERS_OFFLINE=1` enforced at entry (raises `RSISafetyViolation` if missing), alignment gate mandatory before `make deploy`, Ansible Vault for all credentials, NATS quorum checked before PPO checkpoint. No full retrain required for skill additions. Makefile: `make train-ppo`. 49/49 offline tests.

- [ ] **Projector dimension alignment** -- Regenerate `spatial_tensors_v1.safetensors` with real sensor-dimension vectors (5D/8D) when all sensor pipelines are in production. Retrain each projector head from real data. All projector heads must be rebuilt when `hidden_dim` changes -- coordinate with Model C upgrade.

- [ ] **Federated training across air-gaps** -- For multi-tenant sovereign deployments, implement federated averaging across tenant-specific LoRA adapters. Each tenant trains on their own operator feedback; adapters are merged at the federated coordinator without raw data exchange. LoRA merge uses weighted averaging by tenant alert volume.

- [ ] **Llama-4 Scout upgrade (Model B)** -- When QLoRA is stable on MoE models, evaluate Scout's 10M context for nettap Track 4 (full session corpus rather than windowed samples). Requires custom gradient routing for MoE expert layers.

- [ ] **Model C hidden_dim upgrade** -- Migrate from Llama-3.1-8B (4096D) to Llama-3.3-70B (8192D) on a dedicated GPU node. Set `hidden_dim=8192` in `model_config.toml` and rebuild all projector heads. Coordinate with projector dimension alignment milestone.

- [ ] **Formal alignment audit (standing CI gate)** -- Promote `tests/Execute-CognitiveBypass.sh` and `tests/Invoke-CrossPollinationStress.py` from manual red team playbooks to mandatory CI gates in `make deploy`. Any production weight swap blocked unless both pass. Gate failure dumps full conversation logs and blocks the pipeline until a human reviews.

---

## Configuration Reference

### model_config.toml
Controls base model selection. No script hardcodes model names -- all resolve through `model_config.py`.

```toml
[models.b]
hf_id = "mistralai/Mistral-Small-3.1-24B-Instruct-2503"  # Model B base

[models.c]
hf_id = "meta-llama/Llama-3.1-8B-Instruct"               # Model C base
hidden_dim = 4096                                          # CRITICAL: must = base model hidden_size

[models.d]
hf_id = "google/gemma-3-4b-it"                            # Model D base
```

### Environment Variables
All paths and model IDs can be overridden without editing TOML:

```bash
NEXUS_MODEL_C_BASE=/local/path/to/model    # Override base model path
NEXUS_MODEL_C_HIDDEN_DIM=3840              # Override if switching to Gemma-3-9B
NEXUS_ADAPTERS_DIR=/mnt/nvme/adapters      # Override adapter storage path
ANTHROPIC_API_KEY=sk-ant-...               # Required for 05_synthetic_data_gen.py
```

### nexus.toml → `[nexus.named_vectors]`
Must stay in sync with `SOURCE_VECTOR_MAP` in `generate_golden_datasets.py` and `VECTOR_DIMS` in `projector.py`:

```toml
[nexus.named_vectors]
c2_math       = {size = 8,  distance = "Cosine"}
sentinel_math = {size = 5, distance = "Cosine"}
windows_math  = {size = 4, distance = "Cosine"}
cloud_flow    = {size = 5, distance = "Cosine"}
network_tap   = {size = 8, distance = "Cosine"}
```
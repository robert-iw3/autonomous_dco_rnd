# Tests

All validation for `project_empros`. Every feature, sensor, and service contract must have a test here before it goes anywhere near production. No exceptions.

---

## Containerized test pipeline (primary workflow)

After any codebase change, run tests through the containerized pipeline from the **repo root**:

```bash
# Auto-detect what changed vs HEAD~1 and run only affected sections
./project_empros/tests/run_tests.sh

# Run all 6 sections (full regression)
./project_empros/tests/run_tests.sh --full

# Run a single section
./project_empros/tests/run_tests.sh --section offline
./project_empros/tests/run_tests.sh --section sensors
./project_empros/tests/run_tests.sh --section "mlops services"

# Run all sections in parallel
./project_empros/tests/run_tests.sh --full --parallel

# Force-rebuild images (bypass layer cache)
./project_empros/tests/run_tests.sh --full --rebuild

# Diff against a specific branch instead of HEAD~1
./project_empros/tests/run_tests.sh --base main

# List all sections and their change-detection triggers
./project_empros/tests/run_tests.sh --list
```

Each section runs in an **ephemeral container**: built → tested → report written → image deleted. JUnit XML reports land in `tests/reports/` on the host and are preserved between runs.

### Sections

| Section | Dockerfile | What it tests | Base image |
|---------|-----------|---------------|------------|
| `offline` | `Dockerfile.offline` | TurboVec, RSI loop (107 tests, ~0.3s) | Alpine 3.23 |
| `sensors` | `Dockerfile.sensors` | 14 sensor pipeline contracts + HMAC transmission + e2e sensor pipeline | Alpine 3.23 |
| `mlops` | `Dockerfile.mlops` | Data flow, Track 6 dry-run, TI ingest, eval minilab, s3 parquet worker | Debian slim |
| `analytics` | `Dockerfile.analytics` | LLM hunter (incl. review board + AI controls), agentic swarm, redteam bypass | Alpine 3.23 |
| `services` | `Dockerfile.services` | Worker/infra/orchestration source contracts (255 tests) | Alpine 3.23 |
| `pipeline` | `Dockerfile.pipeline` | Phase 1/2/3 pipeline, guardrails, mlops serving/train | Debian slim |
| `detchamber` | `Dockerfile.detchamber` | Det Chamber engine + acquisition + intake/detonation lifecycle | Alpine 3.23 |
| `siem` | `Dockerfile.siemfed` | SIEM-federated investigation mock E2E (CIM/ECS fanout → mock Splunk/Elastic → swarm pivot + counterpart disproof + conservation) | Alpine 3.23 |

> `mlops` and `pipeline` use `python:3.12-slim` (Debian glibc) because PyTorch CPU wheels link against glibc symbols absent from musl libc.

### Change → section mapping

The script maps changed file paths to sections automatically:

| Changed path | Sections triggered |
|---|---|
| `mlops/scripts/` | offline, mlops, pipeline |
| `analytics/llm_hunter/` | analytics, services |
| `services/` | services |
| `services/worker_ti_ingest/` | mlops |
| `windows/` | pipeline, sensors |
| `infra/`, `linux/`, `infrastructure/` | sensors, services |
| `tests/sensors/` | sensors |
| `tests/test_phase*` | pipeline |
| `tests/lab_analytics_*`, `tests/lab_redteam/` | analytics |

### Reports

**Every test run produces a JUnit report in `tests/reports/`.** Two mechanisms guarantee it:

1. **Section runners** pass an explicit `--junit-xml=/reports/<section>.xml`, producing the
   canonical per-section reports below. These are **committed** (CI-ingestible by Jenkins / GitHub
   Actions / GitLab CI) and persist after the ephemeral containers are removed.
2. **Any other invocation** (host `pytest`, a single-file ad-hoc run) gets a report auto-assigned
   by [`conftest.py`](conftest.py), named from the selected path(s) — e.g.
   `pytest tests/lab_analytics_hunter/test_ai_controls.py` writes
   `tests/reports/test_ai_controls.xml`. These ad-hoc reports are **gitignored** (see
   [`reports/.gitignore`](reports/.gitignore)) so they never clutter commits; the canonical
   section reports are the only ones tracked.

```
tests/reports/
├── offline.xml      ┐
├── sensors.xml      │
├── mlops.xml        │  canonical per-section reports (committed)
├── analytics.xml    │
├── services.xml     │
├── pipeline.xml     │
├── detchamber.xml   │
└── siem.xml         ┘
```

**Coverage is enforced.** [`test_report_coverage.py`](test_report_coverage.py) (host-only) asserts
that *every* `test_*.py` under `tests/` is either run by a report-emitting section or listed (with
justification) as a live-infra / host-only exclusion. An orphaned test — one that no section runs,
so it would never produce a report — is a hard CI failure. Live-only labs (`lab_nats_ingress`,
`lab_qdrant_pipeline`, `lab_middleware`, `test_model_regression.py`) still emit a report via
`conftest.py` when run against their infrastructure.

---

## Running tests (manual / development)

```bash
# Full offline suite (fast, no services needed)
pytest tests/sensors/ tests/lab_s3_worker/ tests/lab_agentic_swarm/ tests/lab_redteam/ \
  tests/lab_mlops_train/test_pyrit_eval.py tests/lab_mlops_train/test_rsi_loop.py \
  tests/test_cross_source_temporal.py tests/test_worker_ti_ingest.py \
  tests/test_turbovec_mlops.py -q

# Single lab
pytest tests/lab_nats_ingress/ -v

# All labs that require live infra (bring up the relevant docker-compose first)
pytest tests/ -m integration -v

# Sensor tests only
pytest tests/sensors/ -v

# S3 live (requires MINIO_ENDPOINT set)
pytest tests/lab_s3_worker/ -m s3_live -v
```

## Test categories

### Offline (no services, CI-safe)

These run in under 5 seconds with no Docker, no GPU, no network. They read source files, build mock data, and prove invariants. The entire `tests/sensors/` and most `lab_*` directories are offline by default.

### Integration (requires docker-compose)

Tests marked `integration` or in labs with a `docker-compose.yml` need live services. Each lab has its own compose file. Bring up only what's needed.

### Live infra (s3_live, ollama)

`@pytest.mark.s3_live` requires `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`. `@pytest.mark.ollama` requires a running Ollama instance. Both are skipped automatically when the environment is absent.

---

## Sensor tests (`tests/sensors/`)

One file per sensor. Each file validates the full sensor pipeline contract: source structure, HMAC signing, Parquet schema, mock data construction, nexus.toml alignment, and worker_qdrant routing. All offline.

| File | Sensor | Vector | Identifier |
|---|---|---|---|
| `test_trellix_sql_pipeline.py` | Trellix ENS (SQL) | trellix_math 6D | `event_id` |
| `test_trellix_pipeline_simulation.py` | Trellix (simulation) | trellix_math 6D | `event_id` |
| `test_sensor_sysmon.py` | Windows Sysmon | windows_math 6D | `sysmon_event_id` |
| `test_windows_xdr_sensor.py` | Windows XDR unified agent | EdrRow/C2Row | `sensor_subtype` |
| `test_sensor_windows_c2.py` | Windows XDR C2Row | c2_math 8D | `process` |
| `test_sensor_windows_deepsensor.py` | Windows XDR EdrRow | deepsensor_math 4D | `event_id` |
| `test_sensor_linux_c2.py` | Linux C2 (eBPF) | c2_math 8D | `id` |
| `test_sensor_linux_sentinel.py` | Linux Sentinel | sentinel_math 5D | `event_id` |
| `test_sensor_macos.py` | macOS sensor (placeholder) | windows_math 6D | `plist_path` |
| `test_sensor_suricata.py` | Suricata EVE | c2_math 8D (pre-computed) | `community_id` |
| `test_sensor_network_tap.py` | Network tap (Arkime ML gateway) | network_tap 8D | `session_id` |
| `test_sensor_cloud_gcp.py` | GCP (Audit/SCC/VPC) + VMware | cloud_flow 5D | `record_id` |
| `test_sensor_cloud_aws.py` | AWS (CloudTrail/GuardDuty/VPC) | context-only (0D) | per-connector |
| `test_sensor_cloud_azure.py` | Azure (Activity/EntraID/NSG) | context-only (0D) | per-connector |

**What each sensor test file covers:**

- **Source structure** -- Cargo.toml, transmitter.rs, docker-compose or deployment artifact exists
- **HMAC signing** -- `X-Batch-HMAC` header, canonical message format (`parquet ‖ seq_BE ‖ sensor_id ‖ ts_BE`), big-endian `to_be_bytes`
- **Parquet schema** -- all vector columns present, correct identifier column
- **Mock data** -- build a valid batch in-memory, Parquet roundtrip, ZSTD codec verified via row group metadata
- **nexus.toml alignment** -- `[schema_mappings.<sensor>]` block has correct `identifier_column`, `vector_name`, `vector_columns`
- **worker_qdrant routing** -- `main.rs` branches on the correct `active_source_type` string with the right vector dimension

**macOS sensor note:** `test_sensor_macos.py` skips source structure tests -- `macos/macos_sensor` is not implemented yet. The nexus.toml placeholder mapping is validated. Tests will be un-skipped when the sensor is built.

---

## Lab tests (`tests/lab_*/`)

Each lab isolates one layer of the pipeline.

### Lab 3: Sensor → Ingress → NATS (`lab_nats_ingress/`)

**Requires:** `docker compose -f tests/lab_nats_ingress/docker-compose.yml up -d`

Proves the transmission path end-to-end:
- HMAC-SHA256 signing from sensor → ingress verification
- Sequence counter gap detection (out-of-order, replay)
- Cross-OS collision detection → 403 + ban
- Temporal drift rejection (timestamps stale >120s)
- Valid payloads publish to `nexus.{type}.telemetry`
- Invalid payloads rejected with correct HTTP codes

### Lab 4: Qdrant Vector Worker Pipeline (`lab_qdrant_pipeline/`)

Validates `worker_qdrant`:
- All sensor types route to the correct named vector space
- Per-sensor vector normalization: `windows_math` (grant_access_score, driver_trust_score), `sentinel_math` (path_depth, entropy), `c2_math` (log-scale interval)
- Anomaly tripwire at `anomaly_score >= 0.88` publishes to `nexus.alerts.math`
- Vectors stored as cosine-normalized unit length

### Lab 5: Middleware ETL Fanout (`lab_middleware/`)

**Requires:** `docker compose -f tests/lab_middleware/docker-compose.yml up -d --build`

Validates the middleware fanout:
- HMAC-stamped Parquet → ingress → NATS publish
- CIM field mappings → Splunk HEC output
- ECS field mappings → Elastic bulk output
- `worker_nexus` re-stamps HMAC and forwards Parquet
- Partial batch failures → DLQ (never silently dropped)
- Circuit breaker fires after repeated destination failures

### Lab 6: Sensor Transmission Layer (`lab_sensor_transmission/`)

Offline regression guard for the HMAC field-order bug discovered during Lab 6: the nexus_integrity stamper had `seq_LE ‖ ts_LE ‖ sensor_id ‖ parquet` instead of the canonical `parquet ‖ seq_BE ‖ sensor_id ‖ ts_BE`. Every Rust sensor batch was silently rejected; sensors banned after 5 attempts.

Proves: correct field order and endianness for every sensor's HMAC stamping.

### Lab 7: MLOps QLoRA Training Smoke (`lab_mlops_train/`)

**Requires:** GPU (8GB+)

Validates the `SpatialProjector` + `NexusMultimodalTrainer` training pipeline using GPT-2 (stand-in for Llama-3.1-8B). Proves: all 7 projector heads initialize correctly, `<|spatial_vector|>` token injection works, LoRA adapter saves/reloads clean.

### Lab 9: Worker Rules Contracts (`lab_worker_rules/`)

Offline. Reads `services/worker_rules/src/main.rs` and validates:
- Duck-typing column sentinels for all sensor types
- Layer A (edge pass-through) and Layer B (centralized rules: LotL, DGA, cloud API, identity, GuardDuty, TLS, Windows bins)
- Circuit breaker parameters, alert JSON schema, Redis queue key consistency, Prometheus metric names

### Lab Red-Team: Cognitive Bypass CI Gate (`lab_redteam/`)

Offline. Promotes `tests/simulation/Execute-CognitiveBypass.sh` from a manual playbook to a structured pytest gate. No live agents, NATS, or LLMs required. 50 tests covering:

| Area | What is checked |
|---|---|
| `wrap_untrusted()` tag structure | Envelopes output in `<untrusted_payload>` tags |
| HTML escape break-out defense | `</untrusted_payload>` in adversarial payload HTML-escaped; outer tags intact |
| SYSTEM OVERRIDE / STATE_UPDATE_SUCCESS | Wrapped as inert data inside envelope |
| Control token defang | `<\|im_start\|>`, `[INST]`, role-play prefixes neutralized |
| DuckDB SQL injection: DDL/DML | Word-boundary regex blocks `DROP`, `DELETE`, `INSERT`, etc. |
| DuckDB SQL injection: local FS | `read_csv('/etc/...')` blocked; `s3://` sources allowed |
| DuckDB ephemeral sandbox | `:memory:` database prevents persistent schema injection |
| `disabled_filesystems` guardrail | `SET disabled_filesystems='LocalFileSystem'` applied |
| LIMIT auto-injection | Prevents unbounded context blowout |
| WARNING notice | Always included in DuckDB output |
| Truncation defense | `MAX_FIELD_LENGTH=10000`; long strings truncated before wrap |
| Dual-path neutralization | DNS subdomain (Path A) and HTTP URI (Path B) both sanitized |
| DLP scrub boundary | Public IPs (185.x) pass through; RFC 1918 (10.0.0.50) masked |
| Playbook contract alignment | Playbook references verified against live sanitizer source |

### Lab 8: Agentic Swarm Pipeline Contracts (`lab_agentic_swarm/`)

Offline. Stubs NATS, LangGraph, and Prometheus; imports `orchestrator.py`, `state.py`, and `sanitizer.py` directly. 85 tests covering:

| Area | What is checked |
|---|---|
| Alert schema | All 20+ `source_type` literals; `anomaly_score` bounds (0–1); `raw_event` default |
| SOAR schema | Blast-radius cap (max 5 targets); enum-only `action_type`; confidence bounds |
| `_initial_route()` | Deterministic first-hop: cloud→`cloud_expert`, network_tap→`nettap_expert`, c2→`net_expert`, endpoint→`host_expert` |
| `supervisor_router()` | True positive → `review_board`; false positive / no verdict → `response_agent` |
| Canary generation | `CANARY_<12hex>` format; uniqueness across 100 calls |
| Sanitizer | Token defang, HTML escape, field truncation, RFC 1918 DLP scrub |
| Canary leak guard | Guard present in `trigger_swarm`; fires before normal-path `_dispatch_soar` |
| DLQ | Published on `GraphRecursionError` AND catch-all `Exception`; DLQ failure absorbed |
| Timeout | Escalates to `manual_review_required` via `_dispatch_soar`; no DLQ |
| NATS subjects | `nexus.alerts.>`, `nexus.soar.execute` (lowercase), `nexus.dlq.cognitive` |
| State keys | `next_agent`, `verdict`, `incident_report`, `action_payload`, `canary` |
| Graph topology | All 7 agent nodes; expert nodes return to supervisor; review_board→response_agent |
| DoS guard | `_investigation_sema` wraps `trigger_swarm` body |
| DLP scrub | `scrub_outbound_dlp()` applied in `_dispatch_soar` |
| Do-not-pivot | DNS resolvers, loopback, link-local metadata in `GLOBAL_DO_NOT_PIVOT` |

### Lab 10: Analytics LLM Hunter Contracts (`lab_analytics_hunter/`)

Offline. Validates `analytics/llm_hunter`: schemas, routing logic, sanitization, entity reducers, security controls. `langchain_core` is stubbed so tests run without the package.

### Lab 11: Operations Contracts (`lab_operations_contracts/`)

Offline. Validates `containment.toml` TOML validity, cloud routing completeness, EDR/firewall fallback definitions, `streams_init.sh` creates all 9 required NATS streams with correct subjects and quorum replica count.

### Lab 12: Infrastructure Hardening (`lab_infra_contracts/`)

Offline. Validates Ansible SSH hardening role (drop-in config, moduli, client hardening), kernel hardening role (sysctl, core dumps, `/tmp noexec`), and `production.yaml` cluster sizes.

### Lab 13: MLOps Serving Contracts (`lab_mlops_serving/`)

Offline. Validates `model_config.toml` structure, all pipeline scripts exist and are syntactically valid Python, air-gap compliance (`TRANSFORMERS_OFFLINE` not overridden to `0`).

### Lab 14: Orchestration CI/CD Contracts (`lab_orchestration/`)

Offline. Validates all 7 pipeline scripts present, `master-ci.yml` stage order, `TRIGGER_MLOPS` gate on training, shell script shebangs, `production.yaml` keys consistent with CI expectations.

### ADDON Phase 2: PyRIT Evaluator (`lab_mlops_train/test_pyrit_eval.py`)

Offline. Validates `mlops/scripts/03_eval_pyrit.py` -- PyRIT multi-turn attack orchestrator scaffold. 56 tests. Does **not** call `run_scenario()` or `main()` to avoid subprocess overhead; tests only pure-logic helpers.

| Area | What is checked |
|---|---|
| Data structures | `Turn`, `AttackScenario`, `PyRITResult` field defaults; `fail_rate`, `gate_passed` |
| Unsafe token list | ≥5 tokens; `STATE_UPDATE_SUCCESS`, `SYSTEM OVERRIDE`, `developer mode`, `bypass mode` |
| `_check_unsafe_token` | Case-insensitive; safe responses pass; empty string passes |
| `_check_schema_corruption` | `delete_firewall_rules`, `delete_all`, `execute_arbitrary_code` blocked |
| `_check_tp_suppression` | S-2 `container_escape` high-confidence dismissal detected; non-S-2 ignored |
| `_evaluate_offline` | PASS/FAIL verdicts; first FAIL short-circuits; schema and TP checks both gate |
| Simulated safe responses | No unsafe tokens; valid JSON; injection attempts → `manual_review_required` |
| Scenario library | ≥5 scenarios; each ≥5 turns; IDs unique; S-1–S-5 all present |
| Air-gap | `PYRIT_OFFLINE` env var used; `MODEL_URL` defaults to localhost; no external API URLs |
| Runner source contract | `list(scenario.turns)` snapshot before loop -- infinite-loop bug provably absent |
| Hard-negative schema | `scenario_id`, `fail_reason`, `rejected_prompt`, `source`, `timestamp` all present |

### ADDON Phase 3: Cross-Source Temporal Corpus (`test_cross_source_temporal.py`)

Offline. Validates both `mlops/corpus_templates/cross_source_temporal.py` and `mlops/scripts/stage_cross_source_temporal.py` (5 classes) plus the alias sync in `mlops/corpus_templates/corpus_utils.py`. 57 tests, 0.08s.

| Area | What is checked |
|---|---|
| TOOL_CLASSES registry | Exactly 5 classes; MITRE lists non-empty; TP/FP generators callable |
| New class: LinuxBeaconAfterExec | linux_sentinel + network_tap in prompt; `/tmp/` path; `cert_self_signed=True`; uid=998 FP |
| New class: CloudLateralMovement | azure_entraid + aws_cloudtrail in prompt; `impossible_travel`; `AttachUserPolicy`; Azure AD Connect FP |
| Record shape | 3-turn message list (system/user/assistant); `source_type=multi_sensor`; `ttp_category=CrossSourceTemporal` |
| TP/FP classification | TP → `TRUE POSITIVE` + contain/isolate/block/revoke; FP → `FALSE POSITIVE` + `RECOMMENDED_ACTION: dismiss` |
| S3_QUERIES | 5 classes covered; no empty WHERE; `comm` field + `/tmp/` for linux; `result_type` + `Sign-in` for cloud |
| corpus_utils.py sync | `SENSOR_FIELD_ALIASES` and `_apply_aliases()` present in `mlops/corpus_templates` copy; values match `mlops/scripts` copy |
| `fmt_edr()` aliases | Live sensor field names (`path`→`Image`, `command_line`→`CommandLine`) correctly mapped |
| Cross-copy sync | Both staging scripts have identical TOOL_CLASSES keys, S3_QUERIES keys, and MITRE techniques |

### ADDON Phase 4: RSI Loop Contracts (`lab_mlops_train/test_rsi_loop.py`)

Offline. Validates `mlops/scripts/08_rsi_loop.py` -- closed-loop RSI orchestrator. 49 tests. No subprocess calls; `RSI_DRY_RUN=1` throughout.

| Area | What is checked |
|---|---|
| `SkillEntry` schema | Confidence floor 0.95; `skill_id`/`trigger_pattern` required; invalid `sandbox_verdict` rejected |
| Remediation action | Exactly 3 required fields; extras rejected; base64 validity; no empty strings |
| Skill library I/O | `promote_skill` writes JSONL; appends without overwrite; `load_skill_library` roundtrip; file path matches ADDON spec |
| Safety invariants | ≥6 invariants; air-gap, NATS quorum, Ansible Vault, alignment gate all present; `RSISafetyViolation` raises on `TRANSFORMERS_OFFLINE!=1` |
| Sandbox verdict counter | Absent file → 0; cursor arithmetic; `_read_new_verdicts` returns typed dicts |
| Threshold guard | Returns `3` when below `SANDBOX_BATCH_THRESHOLD`; default is 50 |
| Dry-run full cycle | `rsi_loop(dry_run=True)` returns `0`; `main(["--dry-run"])` returns `0` |
| Schema violation logging | `_log_schema_violation` writes timestamped JSON to violations dir |
| Source contracts | `skill.update` NATS subject; `_AIRGAP_ENV` injected into all subprocesses; alignment gate before `"deploy"` make target; safety check before `"train-ppo"` |

---

## Root-level tests

| File | What it tests |
|---|---|
| `test_data_flow.py` | End-to-end data transformation: Track 1 (spatial) tensor format, Track 4 (nettap SPI) 44-column schema, Hive partition columns for DuckDB discovery |
| `test_e2e_sensor_pipeline.py` | Full sensor → MLOps → Qdrant path: schema, HMAC, Parquet shape, S3 routing, vector dims -- offline by default, `integration` mark for live infra |
| `test_model_regression.py` | Model output schema compliance (Pydantic), topological accuracy, blast radius safety with governance context, nettap forensics output schema |
| `test_phase1_pipeline.py` | Phase 1 scripts offline: `06_sandbox_runner.py` (arg substitution, dry-run queue I/O), `07_feed_ingest.py` (4-stage filter, kill chain parsing), `BeaconML.py` flow-stat field computation |
| `test_phase2_pipeline.py` | Phase 2 scripts offline: `05_critic_loop.py` (NeMo schema, critic loop I/O, DLQ routing), `02_train_qlora.py` (PPO flag, reward model integration, checkpoint logic) |
| `test_phase3_guardrails.py` | Phase 3 config offline: NeMo guardrails schema/input/output rules, `garak_config.yaml` spec compliance, `vault_client.py` interface + error handling + caching |
| `test_s3_query_alignment.py` | Production column name validation for Track 6 S3 queries -- catches name mismatches between sensor Parquet and MLOps query index |
| `test_track6_dryrun.py` | Track 6 semantic correctness: for every tool class in every staging query index, generates a synthetic TP row and proves the WHERE clause returns it via in-memory DuckDB |
| `test_worker_contracts.py` | Source-level regression guard for P1 safety fixes: partial containment failure → Err, partial S3 upload → Err, on_disk_payload + wal_config in qdrant_init.sh, circuit breaker state machine |
| `test_worker_ti_ingest.py` | TI RAG service offline validation: sliding-window chunker, format detection (PDF/STIX/Sigma/JSONL/IOC CSV), all parsers, BM25Index, TurboVec numpy fallback, HybridRetriever (add/remove/search/sensor-filter/list_docs), CrossEncoder fallback, API contract shapes, module exports. 90 passing / 2 skipped (BM25 path skips if rank_bm25 absent). No GPU, no Qdrant, no NATS required. |
| `test_turbovec_mlops.py` | TurboVec MLOps integrations offline validation: TurboVecNgramIndex (vectorize, add/search, meta, size, sequential IDs, numpy fallback), TurboVecDeduplicator (first-add, exact dup, threshold 0.0, size tracking), HardNegativeMiner (empty index, index_record, cross-class filter, result schema, k-limit, prompt extraction), SkillDeduplicator (load_from_library, find_duplicate, add, skill text determinism), spool_ttp_behavioral dedup wiring (flag, signature, threshold arg, dedup logic), critic loop `_append_mined_negatives` (schema, empty list, prompt exclusion), `promote_skill` near-dup guard + singleton warm from file. 58/58 passing, 0.14s. No GPU, no services required. |

---

## S3/MinIO lab (`tests/lab_s3_worker/`)

Validates that all 14 sensor types produce well-formed Parquet and deliver it correctly to MinIO.

Sensor types covered: `trellix_sql`, `sysmon_sensor`, `macos_sensor`, `linux_sentinel`, `linux_c2`, `windows_deepsensor`, `suricata_eve`, `windows_c2`, `network_tap`, `gcp_audit`, `gcp_scc`, `gcp_vpc`, `aws_cloudtrail`, `aws_guardduty`.

Test classes:

- `TestParquetConstruction` -- per-sensor schema is valid, Parquet roundtrip works, ZSTD codec applied (verified via row group metadata)
- `TestPartitionPathFormat` -- Hive partition key matches `telemetry/{sensor_type}/dt=YYYY-MM-DD/hour=HH/{uuid}.parquet`
- `TestS3PartitionDiscovery` -- in-memory object store simulation proves partition discovery works across all 14 types, no external MinIO needed
- `TestMinIOLiveIntegration` -- `@pytest.mark.s3_live`: writes real Parquet to MinIO, verifies key structure and content, skipped unless `MINIO_ENDPOINT` is set

---

## Simulation scripts (`tests/simulation/`)

Not pytest tests -- standalone scripts for adversarial and stress validation. Run manually against a live deployment.

| Script | Purpose |
|---|---|
| `Detonate-MathTripwire.py` | Injects a mathematically perfect anomaly to test tripwire detection paths (gateway, NATS, baseline routing) |
| `Inject-BenignBaselineFlood.py` | Floods the pipeline with benign baseline traffic to stress-test false-positive rate |
| `Invoke-CrossPollinationStress.py` | Sends mixed sensor types in parallel to test worker_qdrant routing under load |
| `Test-SovereignAirGap.py` | Proves BOTH inference paths (vLLM GPU + Model A CPU) are air-gapped by poisoning DNS and verifying no network calls are made |
| `Invoke-NexusC2Simulation.ps1` | Windows PowerShell C2 simulation |
| `Invoke-SoarLatencyRace.ps1` | SOAR containment action latency test |
| `Execute-CognitiveBypass.sh` | Adversarial prompt injection attempt against the LLM Hunter |
| `Simulate-NamespaceEscape.sh` | Container namespace escape attempt validation |
| `Validate-ActiveDefenseHUD.ps1` | Active defense HUD readiness check |

---

## Adding a new test

### For a new sensor

1. Create `tests/sensors/test_sensor_<name>.py` using an existing file as a template (e.g., `test_sensor_linux_sentinel.py` for a Linux sensor, `test_sensor_cloud_aws.py` for a cloud connector).
2. Cover these six classes: `TestSourceStructure`, `TestRustSource` (or equivalent), `TestMockParquet`, `TestNexusConfig`, and a `TestWorkerQdrant` check for the routing branch.
3. Verify:
   - `X-Batch-HMAC` header present in transmitter source
   - HMAC canonical format: `parquet ‖ seq.to_be_bytes() ‖ sensor_id ‖ ts.to_be_bytes()`
   - Parquet ZSTD codec confirmed via `pq.read_metadata()` row group metadata -- do NOT compare file sizes (Parquet's own encoding makes this fragile for small batches)
   - `[schema_mappings.<sensor>]` block in `services/config/nexus.toml` with correct `identifier_column`, `vector_name`, `vector_columns`
   - `worker_qdrant/src/main.rs` branches on `active_source_type == "<sensor>"` with `raw_math.len() == <N>`
4. Add the sensor to `ALL_SENSOR_TYPES` in `tests/lab_s3_worker/test_s3_parquet_ingestion.py` with a batch builder and identifier key.
5. Run `pytest tests/sensors/test_sensor_<name>.py -v` -- all tests must pass before merging.

### For a new service or worker

1. Create `tests/lab_<name>/test_<name>.py`.
2. If it needs live services, add a `docker-compose.yml` and a `README` in the lab directory.
3. Mark integration tests with `@pytest.mark.integration` and skip if services unavailable using `pytest.importorskip` or an environment check.
4. Cover: source structure, key invariants readable from source (no compilation needed), and any mock-able runtime behavior.

### For a new MLOps script

1. Add a test case to the appropriate `test_phase*.py` file.
2. Keep it offline: read the script source or import it with mocked dependencies.
3. If the script has a `--dry-run` flag, exercise it.

### Security invariants that must always be tested

Every sensor test must verify:

- **No plaintext secrets** -- active (non-commented) credential fields must be `${ENV_VAR}`, empty, or an ALL_CAPS_UNDERSCORES deployment placeholder. Actual secret values are a test failure.
- **HTTPS enforcement** -- `gateway_url` and any nexus URL must start with `https://`.
- **HMAC present** -- `X-Batch-HMAC` (or `HDR_BATCH_HMAC`) and `X-Batch-Sequence` headers must be present in the transmitter source.
- **ZSTD compression** -- all Parquet output must use ZSTD codec. Verify via `pq.read_metadata()`, not file size.
- **Sequence counter persisted** -- Python sensors use SQLite `integrity_sequence` table; Rust sensors use `.transmit_sequence` file or in-memory struct (Suricata). Must be verifiable from source.

### Offline-first rule

If a test can be written offline (reading source files, building mock data), it must be. Live-infra tests are a last resort for things that cannot be proven without running services. The sensor tests prove this is achievable for almost everything -- 743 tests run in under 2 seconds with no Docker.

---

## pytest marks

| Mark | Meaning | Skip condition |
|---|---|---|
| `integration` | Requires live Docker services | Not in integration environment |
| `s3_live` | Requires MinIO/S3 endpoint | `MINIO_ENDPOINT` not set |
| `ollama` | Requires running Ollama instance | Ollama not reachable |

Register new marks in `tests/pytest.ini`.

---

## Config files

| Path | Purpose |
|---|---|
| `tests/config/nexus.toml` | Nexus schema registry used by integration tests and some sensor tests as a fallback |
| `tests/pytest.ini` | pytest mark registration |
| `tests/requirements.txt` | Test dependencies |
| `tests/requirements.in` | Source for `pip-compile` |

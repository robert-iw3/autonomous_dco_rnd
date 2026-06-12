# Changelog -- Arkime Network Defense Stack: Network Baseline Pipeline

## Gateway resilience + throughput + end-to-end data-flow stress lab

**Goal: survive a core-switch firehose without silent failure or data loss, and
prove it under escalating load.** Driven by the scalability/error-handling review.

### ML gateway (Rust) -- auto-recovery + throughput

| Change | Rationale |
|---|---|
| New `supervisor.rs`: `supervise()` restarts a faulting task (ingest/transmit) with capped exponential backoff and, once it exhausts its budget, returns `Err` so `main` exits non-zero for a clean orchestrator restart. `main.rs` wires both pipelines through it + a fatal flag. | A returned `Err` used to just log "halted" and leave the gateway "up" with a dead pipeline -- a **silent data blackhole**. Tasks now self-heal or fail loudly. Unit-tested (restart-until-healthy, give-up-after-budget, cancel-before-start). |
| `spool_db.rs`: per-row `INSERT` loop → **chunked multi-row `INSERT`** (`QueryBuilder`, 400 rows/stmt). | ~400× fewer statement round-trips per batch -- the SQLite write was the inline throughput chokepoint. Round-trip + chunking unit-tested against a real temp DB. |
| `spool_db.rs`: UTF-8-safe `truncate_utf8()` replaces `&s[..n]`. | The old slice **panicked** when the 4096-byte cap landed mid-codepoint on a non-ASCII URI / UA / cert CN -- a real crash-the-task bug. |
| `redis_lookup.rs` + `main.rs`: Redis is now a **soft** dependency -- `supervisor::retry` on connect, then the writer drains+drops and reconnects every 30s. Boot never blocks on Redis. | Redis is a non-critical enrichment cache; a Redis outage must not prevent the gateway from booting or stall the ingest hot path. |
| `redpanda.rs`: `auto.offset.reset` `latest` → **`earliest`**. | `latest` silently skips a backlog already queued in the broker on a cold start / new group -- a data-loss footgun. Committed offsets still win on normal restarts. |
| `redpanda.rs`: `gateway_consumer_heartbeat_seconds` gauge each loop iteration; the compose healthcheck now requires it present + non-zero (was just "/metrics responds"). | The old healthcheck **passed while the consumer was dead/blocked**. Liveness now reflects the pipeline, not just the process. (Prometheus should additionally alert on heartbeat staleness.) |

Verified: `cargo test` in the tier1 image — **11/11 pass** (supervisor 5, spool 4, features 2), compiles clean.

### Data-flow stress lab (`test/lab/`)

A Podman mini-lab mirroring `img/network_defense_stack_data_flow.svg`: a **mock
Gigamon tap** (`loadgen`) dual-writes synthetic Arkime SPI to Redpanda (ML path)
and OpenSearch (forensic path), through the **real gateway** to a `mock-ingress`
(counts Parquet rows). The driver runs escalating tiers (low 1k → medium 20k →
high 100k → very-high 500k), **logs a per-component ledger**, and asserts
conservation on both paths (`opensearch == produced`; `received == produced`,
`accepted == produced − noise`, `spooled == accepted`, `transmitted == accepted`,
`mock rows == accepted`). Any inter-stage leak fails the tier with exact counts.

---

## PCAP retention + SPI durability + infra/deploy test workbench

**Storage model made explicit: metadata is the durable product, packets are transient.**

| Change | Rationale |
|---|---|
| New `infrastructure/sensor_node/pcap_retention.sh` -- purges `/data/pcap` files older than `PCAP_RETENTION_HOURS` (default 72) on a rolling window; dry-run support and a guard that refuses a `0`-hour window (which would wipe everything). | PCAPs grow ~10 TB/day at 1 Gbps. The sensor's value is the extracted SPI metadata, not the raw packets, so captures are a short-term retro-hunt buffer, not durable storage. |
| `startarkime.sh` now spawns an hourly retention loop (initial pass immediate) and tears it down on shutdown; `Dockerfile` ships the script. | Retention runs in-container alongside capture; no external cron needed. |
| `config.ini`: added `freeSpaceG=25%` + `maxFileSizeG=12`. | Size-based safety net so a traffic spike can't fill the disk between hourly purges; granular files keep rotation/retention precise. |
| `opensearch_index.json` (ISM): **removed the `delete` state** (was deleting session indices at 21d). Hot → warm (read-only) → archive (S3 snapshot) is now terminal. | SPI metadata must be RETAINED for historical analysis. Only on-sensor PCAP files are aged out (72h); the searchable session metadata is kept (and S3-archived as the durable historical copy). |
| New `test/` workbench (tier0, pure Python, 45 tests): **security** (mTLS end to end, drop-privileges, loopback-bound management, default-deny firewall, no committed secrets), **performance** (host/NIC tuning, AF_PACKET + NUMA, broker/cluster sizing, gateway batching), **interoperability** (Arkime↔Redpanda topic, gateway↔Nexus 48-col contract, OpenSearch index/ISM alignment), **retention** (executes the real `pcap_retention.sh` against synthetic captures; pins SPI-retained / pcap-72h split). | The infrastructure + deployment is now tested end to end, not just the gateway crate. |

---

## Goal

Optimize the ML Gateway's Parquet output for downstream LSTM-AE training and DuckDB query performance. Add derived ML features that the network baseline model and nettap expert need. Close the missing `max_spool_bytes` safety gap.

---

## config.rs (gateway/src/config.rs)

| Change | Rationale |
|---|---|
| Added `max_spool_bytes: Option<u64>` to `StorageConfig` with default 50GB. | The specs.md identified this as a known gap -- at 50K sessions/sec with the gateway down, the SQLite WAL grows ~100MB/sec. Without a cap, the disk fills and the host crashes. This enforces a configurable ceiling. |
| Added `parquet_row_group_size: usize` to `NexusConfig` with default 50,000 rows. | Larger row groups improve DuckDB predicate pushdown. The default Arrow row group is too small for the network_tap volume -- DuckDB's min/max statistics on `timestamp_start` and `dst_ip` are more effective when each row group covers a meaningful time span. |
| Added `transmit_sort_by_timestamp: bool` to `NexusConfig` with default `true`. | Controls whether the transmitter sorts SQLite rows by timestamp before Parquet serialization. Sorted data enables DuckDB to skip entire row groups during temporal range queries. |

---

## models.rs (gateway/src/models.rs)

| Change | Rationale |
|---|---|
| Added `is_internal_dst: bool` to `NetworkFlowRecord`. | RFC-1918 classification of the destination IP. The LSTM-AE needs this as a binary feature to distinguish internal lateral movement patterns from external C2 traffic without parsing IP strings. The nettap expert SOP already instructs checking RFC-1918 manually -- this pre-computes it. |
| Added `port_class: String` to `NetworkFlowRecord`. | Classifies `dst_port` into `"well_known"` (0-1023), `"registered"` (1024-49151), or `"ephemeral"` (49152-65535). C2 frameworks disproportionately use ephemeral or high registered ports. Pre-classifying saves the LLM from numeric reasoning on raw port numbers. |

---

## features.rs (gateway/src/pipeline/features.rs)

| Change | Rationale |
|---|---|
| Added `is_internal_dst()` helper function. | Checks the destination IP against RFC-1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local (169.254.0.0/16). Pure string parsing -- no DNS lookups, no allocation. |
| Added `port_class()` helper function. | Three-way classification by numeric range. Inlined for zero overhead. |
| Both fields computed in `extract()` and assigned to the `NetworkFlowRecord`. | Computation happens after noise filtering, so only accepted sessions pay the cost (trivial -- two string comparisons and one integer comparison). |

---

## spool_db.rs (gateway/src/storage/spool_db.rs)

| Change | Rationale |
|---|---|
| Added `is_internal_dst` and `port_class` columns to the `CREATE TABLE` statement. | Stores the derived features alongside the raw flow data so the transmitter can include them in the Parquet output without recomputing. |
| Added `ALTER TABLE ... ADD COLUMN` migration block after `CREATE TABLE IF NOT EXISTS`. | Handles existing installations where the SQLite database already has the old schema. SQLite's `ALTER TABLE ADD COLUMN` is a no-op if the column already exists (when wrapped in a try). |
| Added `check_spool_size()` method. | Queries `SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()` to get the current database file size. If it exceeds `max_spool_bytes`, the oldest untransmitted rows are dropped with a logged warning. This is the circuit breaker that prevents disk exhaustion during extended gateway outages. |
| `insert_batch()` now calls `check_spool_size()` before inserting. | Enforcement happens at write time, not read time, so the spool never silently grows past the cap. |

---

## nexus.rs (gateway/src/transmit/nexus.rs)

| Change | Rationale |
|---|---|
| Added `is_internal_dst` and `port_class` to the Arrow schema (2 new columns: Boolean + Utf8). | Carries the derived features through to the Parquet output so downstream consumers (LSTM-AE, nettap expert, worker_qdrant) get them without recomputing. |
| Added corresponding Arrow builders and row population in the serialization loop. | Mirrors the spool_db columns. |
| SQL query now includes `ORDER BY timestamp_start ASC` (already present) and the two new columns. | Ensures sorted output for row-group-level predicate pushdown in DuckDB. |
| `WriterProperties` now uses `set_max_row_group_size(cfg.nexus.parquet_row_group_size)`. | Configurable via `nexus.toml` (default 50K rows). Larger row groups mean fewer row groups per file, and each row group's min/max statistics cover a wider time range, improving DuckDB's skip ratio. |
| Added `X-Partition-Hour` and `X-Partition-Date` headers to the HTTPS POST. | These partition hints are forwarded through NATS to the S3 archiver, enabling Hive-style path construction (`dt=YYYY-MM-DD/hour=HH/`) without the archiver needing to parse the Parquet metadata. |
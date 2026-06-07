# Changelog -- Arkime Network Defense Stack: Network Baseline Pipeline

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
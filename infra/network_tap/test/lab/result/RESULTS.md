# Data-flow validation results

Each tier sends a known count of mock Gigamon/Arkime sessions and TRACKS it as
it reaches every component. The ML path narrows once (intentional noise filter,
accounted — not lost); every hop after must hold 100% of the accepted set, and
the forensic path must hold 100% of everything sent. `% of sent` / `% of accepted`
are the share of data that traversed the pipeline to that hop.

## Summary

| tier | produced | forensic % | ML path % | ML sink % | noise % | sessions/s | verdict |
|---|---|---|---|---|---|---|---|
| low | 1,000 | 100.0% | 100.0% | 100.0% | 14.3% | 267 | PASS |
| medium | 20,000 | 100.0% | 100.0% | 100.0% | 14.29% | 4,143 | PASS |
| high | 100,000 | 100.0% | 100.0% | 100.0% | 14.286% | 12,529 | PASS |
| very-high | 500,000 | 100.0% | 100.0% | 100.0% | 14.286% | 21,770 | PASS |

## Tracker — tier `low` (sent 1,000)

| hop | component | count | % of sent | % of accepted |
|---|---|---|---|---|
| 1_tap_sent | Gigamon tap / Arkime (mock) | 1,000 | 100.0 |  |
| 2_forensic_os | OpenSearch (forensic path) | 1,000 | 100.0 |  |
| 3_broker_gateway | Redpanda → gateway (received) | 1,000 | 100.0 |  |
| 4_filter_accepted | gateway filter (non-noise) | 857 | 85.7 | 100.0 |
| 5_spool_sqlite | SQLite WAL spool | 857 |  | 100.0 |
| 6_transmit_parquet | Parquet → HTTPS | 857 |  | 100.0 |
| 7_ml_sink | Nexus/Axum ingress (ML sink) | 857 |  | 100.0 |

**loss:** forensic=0, ML=0 — **PASS**

### Component processing evidence — `low` (from each container's log)

- **tap_gigamon (loadgen)**
  ```
  {"produced": 1000, "noise": 143, "expected_accepted": 857, "to_opensearch": 1000, "elapsed_sec": 0.99}
  ```
- **broker (redpanda)**
  ```
  INFO  2026-06-12 00:54:53,562 [shard 0:main] tx - [{kafka/arkime-spi-raw/0}] - rm_stm.cc:117 - Setting bootstrap committed offset to: 0
  INFO  2026-06-12 00:54:53,562 [shard 0:rs  ] raft - [group_id:4, {kafka/arkime-spi-raw/0}] vote_stm.cc:443 - became the leader term: 1
  ```
- **gateway spool (SQLite WAL)**
  ```
  {"timestamp":"2026-06-12T00:54:53.674505Z","level":"INFO","fields":{"message":"spooled batch to SQLite WAL (time flush)","rows":1}}
  {"timestamp":"2026-06-12T00:54:54.689147Z","level":"INFO","fields":{"message":"spooled batch to SQLite WAL (time flush)","rows":856}}
  ```
- **gateway transmit (Parquet→HTTPS)**
  ```
  {"timestamp":"2026-06-12T00:54:54.701369Z","level":"INFO","fields":{"message":"transmitted Parquet batch to Nexus","rows":1,"seq":1}}
  {"timestamp":"2026-06-12T00:54:55.717036Z","level":"INFO","fields":{"message":"transmitted Parquet batch to Nexus","rows":856,"seq":2}}
  ```
- **ML sink (mock nexus ingress)**
  ```
  [mock-ingress] batch #1 seq=1: 1 rows (13972 B) -- running total 1 rows
  [mock-ingress] batch #2 seq=2: 856 rows (30149 B) -- running total 857 rows
  ```
- **forensic (opensearch)**
  ```
  index arkime_sessions3-lab: 1000 docs (verified via _count API)
  ```

## Tracker — tier `medium` (sent 20,000)

| hop | component | count | % of sent | % of accepted |
|---|---|---|---|---|
| 1_tap_sent | Gigamon tap / Arkime (mock) | 20,000 | 100.0 |  |
| 2_forensic_os | OpenSearch (forensic path) | 20,000 | 100.0 |  |
| 3_broker_gateway | Redpanda → gateway (received) | 20,000 | 100.0 |  |
| 4_filter_accepted | gateway filter (non-noise) | 17,142 | 85.71 | 100.0 |
| 5_spool_sqlite | SQLite WAL spool | 17,142 |  | 100.0 |
| 6_transmit_parquet | Parquet → HTTPS | 17,142 |  | 100.0 |
| 7_ml_sink | Nexus/Axum ingress (ML sink) | 17,142 |  | 100.0 |

**loss:** forensic=0, ML=0 — **PASS**

### Component processing evidence — `medium` (from each container's log)

- **tap_gigamon (loadgen)**
  ```
  {"produced": 20000, "noise": 2858, "expected_accepted": 17142, "to_opensearch": 20000, "elapsed_sec": 2.04}
  ```
- **broker (redpanda)**
  ```
  INFO  2026-06-12 00:57:41,474 [shard 1:main] tx - [{kafka/arkime-spi-raw/0}] - rm_stm.cc:117 - Setting bootstrap committed offset to: 0
  INFO  2026-06-12 00:57:41,474 [shard 1:rs  ] raft - [group_id:4, {kafka/arkime-spi-raw/0}] vote_stm.cc:443 - became the leader term: 1
  ```
- **gateway spool (SQLite WAL)**
  ```
  {"timestamp":"2026-06-12T00:57:42.997953Z","level":"INFO","fields":{"message":"spooled batch to SQLite WAL","rows":5000}}
  {"timestamp":"2026-06-12T00:57:44.054951Z","level":"INFO","fields":{"message":"spooled batch to SQLite WAL (time flush)","rows":2141}}
  ```
- **gateway transmit (Parquet→HTTPS)**
  ```
  {"timestamp":"2026-06-12T00:57:43.745096Z","level":"INFO","fields":{"message":"transmitted Parquet batch to Nexus","rows":5001,"seq":2}}
  {"timestamp":"2026-06-12T00:57:44.796330Z","level":"INFO","fields":{"message":"transmitted Parquet batch to Nexus","rows":2141,"seq":3}}
  ```
- **ML sink (mock nexus ingress)**
  ```
  [mock-ingress] batch #1 seq=1: 10000 rows (189970 B) -- running total 10000 rows
  [mock-ingress] batch #2 seq=2: 5001 rows (106448 B) -- running total 15001 rows
  [mock-ingress] batch #3 seq=3: 2141 rows (53862 B) -- running total 17142 rows
  ```
- **forensic (opensearch)**
  ```
  index arkime_sessions3-lab: 20000 docs (verified via _count API)
  ```

## Tracker — tier `high` (sent 100,000)

| hop | component | count | % of sent | % of accepted |
|---|---|---|---|---|
| 1_tap_sent | Gigamon tap / Arkime (mock) | 100,000 | 100.0 |  |
| 2_forensic_os | OpenSearch (forensic path) | 100,000 | 100.0 |  |
| 3_broker_gateway | Redpanda → gateway (received) | 100,000 | 100.0 |  |
| 4_filter_accepted | gateway filter (non-noise) | 85,714 | 85.714 | 100.0 |
| 5_spool_sqlite | SQLite WAL spool | 85,714 |  | 100.0 |
| 6_transmit_parquet | Parquet → HTTPS | 85,714 |  | 100.0 |
| 7_ml_sink | Nexus/Axum ingress (ML sink) | 85,714 |  | 100.0 |

**loss:** forensic=0, ML=0 — **PASS**

### Component processing evidence — `high` (from each container's log)

- **tap_gigamon (loadgen)**
  ```
  {"produced": 100000, "noise": 14286, "expected_accepted": 85714, "to_opensearch": 100000, "elapsed_sec": 5.48}
  ```
- **broker (redpanda)**
  ```
  INFO  2026-06-12 00:59:25,477 [shard 1:main] tx - [{kafka/arkime-spi-raw/0}] - rm_stm.cc:117 - Setting bootstrap committed offset to: 0
  INFO  2026-06-12 00:59:25,477 [shard 1:rs  ] raft - [group_id:4, {kafka/arkime-spi-raw/0}] vote_stm.cc:443 - became the leader term: 1
  ```
- **gateway spool (SQLite WAL)**
  ```
  {"timestamp":"2026-06-12T00:59:30.614080Z","level":"INFO","fields":{"message":"spooled batch to SQLite WAL","rows":5000}}
  {"timestamp":"2026-06-12T00:59:31.636513Z","level":"INFO","fields":{"message":"spooled batch to SQLite WAL (time flush)","rows":713}}
  ```
- **gateway transmit (Parquet→HTTPS)**
  ```
  {"timestamp":"2026-06-12T00:59:31.466943Z","level":"INFO","fields":{"message":"transmitted Parquet batch to Nexus","rows":10000,"seq":9}}
  {"timestamp":"2026-06-12T00:59:31.908272Z","level":"INFO","fields":{"message":"transmitted Parquet batch to Nexus","rows":713,"seq":10}}
  ```
- **ML sink (mock nexus ingress)**
  ```
  [mock-ingress] batch #8 seq=8: 10000 rows (188868 B) -- running total 75001 rows
  [mock-ingress] batch #9 seq=9: 10000 rows (188229 B) -- running total 85001 rows
  [mock-ingress] batch #10 seq=10: 713 rows (27109 B) -- running total 85714 rows
  ```
- **forensic (opensearch)**
  ```
  index arkime_sessions3-lab: 100000 docs (verified via _count API)
  ```

## Tracker — tier `very-high` (sent 500,000)

| hop | component | count | % of sent | % of accepted |
|---|---|---|---|---|
| 1_tap_sent | Gigamon tap / Arkime (mock) | 500,000 | 100.0 |  |
| 2_forensic_os | OpenSearch (forensic path) | 500,000 | 100.0 |  |
| 3_broker_gateway | Redpanda → gateway (received) | 500,000 | 100.0 |  |
| 4_filter_accepted | gateway filter (non-noise) | 428,571 | 85.714 | 100.0 |
| 5_spool_sqlite | SQLite WAL spool | 428,571 |  | 100.0 |
| 6_transmit_parquet | Parquet → HTTPS | 428,571 |  | 100.0 |
| 7_ml_sink | Nexus/Axum ingress (ML sink) | 428,571 |  | 100.0 |

**loss:** forensic=0, ML=0 — **PASS**

### Component processing evidence — `very-high` (from each container's log)

- **tap_gigamon (loadgen)**
  ```
  {"produced": 500000, "noise": 71429, "expected_accepted": 428571, "to_opensearch": 500000, "elapsed_sec": 20.49}
  ```
- **broker (redpanda)**
  ```
  INFO  2026-06-12 01:03:09,709 [shard 0:main] tx - [{kafka/arkime-spi-raw/0}] - rm_stm.cc:117 - Setting bootstrap committed offset to: 0
  INFO  2026-06-12 01:03:09,709 [shard 0:rs  ] raft - [group_id:4, {kafka/arkime-spi-raw/0}] vote_stm.cc:443 - became the leader term: 1
  ```
- **gateway spool (SQLite WAL)**
  ```
  {"timestamp":"2026-06-12T01:03:29.859519Z","level":"INFO","fields":{"message":"spooled batch to SQLite WAL","rows":5000}}
  {"timestamp":"2026-06-12T01:03:30.925177Z","level":"INFO","fields":{"message":"spooled batch to SQLite WAL (time flush)","rows":3570}}
  ```
- **gateway transmit (Parquet→HTTPS)**
  ```
  {"timestamp":"2026-06-12T01:03:30.128508Z","level":"INFO","fields":{"message":"transmitted Parquet batch to Nexus","rows":5000,"seq":47}}
  {"timestamp":"2026-06-12T01:03:31.189313Z","level":"INFO","fields":{"message":"transmitted Parquet batch to Nexus","rows":3570,"seq":48}}
  ```
- **ML sink (mock nexus ingress)**
  ```
  [mock-ingress] batch #46 seq=46: 10000 rows (187834 B) -- running total 420001 rows
  [mock-ingress] batch #47 seq=47: 5000 rows (108194 B) -- running total 425001 rows
  [mock-ingress] batch #48 seq=48: 3570 rows (80846 B) -- running total 428571 rows
  ```
- **forensic (opensearch)**
  ```
  index arkime_sessions3-lab: 500000 docs (verified via _count API)
  ```

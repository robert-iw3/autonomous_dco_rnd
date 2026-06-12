# Data-flow stress lab

Spins up the whole pipeline in containers and proves **no data is lost on either path** under escalating load.

```
loadgen (mock Gigamon tap + Arkime)
  ├─ SPI JSON ─► redpanda ─► ml-gateway ─► mock-ingress   (ML training path)
  └─ SPI docs ─► opensearch                                (forensic path)
                                 redis (session cache) ───┘
```

The mock tap dual-writes synthetic Arkime SPI to Redpanda **and** OpenSearch,
exactly as Arkime does. For each tier the driver produces the batch, waits for the
pipeline to drain, **logs a per-component ledger**, and asserts conservation:

| Path | Invariant |
|---|---|
| forensic | `opensearch docs == produced` (keep-all; analysts retain everything) |
| ML | `gateway received == produced`, `accepted == produced − noise`, `spooled == accepted`, `transmitted == accepted`, `mock-ingress rows == accepted` |

Any leak between two stages fails the tier with the exact counts.

## Components (`compose.lab.yml`)
`redpanda` · `opensearch` (single-node) · `redis` · `mock-ingress` (HTTPS, counts
Parquet rows = the nexus-edge/LLM sink) · `ml-gateway` (the real crate) ·
`loadgen` (the mock tap, dual-write).

## Run
```bash
# all tiers (low 1k → medium 20k → high 100k → very-high 500k)
pytest infra/network_tap/test/lab/test_pipeline_stress.py -s -v

# one tier / override sizes
pytest .../test_pipeline_stress.py -s -v -k high
LAB_VERYHIGH=1000000 pytest .../test_pipeline_stress.py -s -v -k very
```
Needs podman (or `LAB_ENGINE=docker`). The first run builds the gateway image
(compiles the Rust crate) — allow time. Tier sizes override via `LAB_LOW`,
`LAB_MEDIUM`, `LAB_HIGH`, `LAB_VERYHIGH`.

## Results (`result/`)
Each tier writes evidence into `result/` (created on run; artifacts git-ignored):
- `tier_<name>.json` — full record incl. a **tracker**: the known sent count logged
  as it reaches each hop (tap → OpenSearch / Redpanda → gateway received → filter →
  spool → transmit → ML sink), with `% of sent` / `% of accepted` at every hop.
- `summary.json` — all tiers.
- `RESULTS.md` — a summary table (forensic %, ML path %, ML-sink %, noise %, verdict)
  plus a per-tier tracker waterfall.

The tracker reconciles end to end: the **forensic path must show 100% of sent**, and
every ML hop **after** the noise filter must show **100% of the accepted set** — the
percentage of data that traversed the pipeline with zero loss. A non-100% (non-noise)
hop is data loss and fails the tier.

## What it proves
Real, end-to-end: that the gateway keeps up and loses nothing as load climbs, and
that the resilience changes (supervised tasks, multi-row spool insert, Redis
degrade, `earliest` offset) hold under a moving stream. The `result/` tracker is the
evidence each component handled every session.

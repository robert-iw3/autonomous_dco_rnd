# data_ops/ — Conceptual Testing Phase (v0.2, implementation candidate)

> **Status: implementation candidate, pending live validation.** The DAG and
> Spark job are now written against the real contracts (S3 layout, env vars,
> CODE_GRAPH.md store consumers) and are intended to run as-is against a dev
> MinIO bucket — but no data has been run through them yet, and nothing is
> wired into the deployed pipeline. v0.1 was pseudocode; v0.2 is testable.

## Why this exists

The hot path (`sensor → HAProxy → core_ingress (Axum) → NATS JetStream →
worker_qdrant / worker_rules / worker_s3_archive → Qdrant + S3`) is
deliberately lean and stays untouched by anything in this directory. See the
architecture discussion that motivated this: current design was evaluated
against Airflow, Cassandra, Flink, Hadoop, Kafka, Spark, and NiFi, and only
Airflow (orchestration) + Spark (batch compute) made sense as a **cold-path
addition** — everything else either duplicates a component already handled
better by NATS/Qdrant, or fights the low-latency/memory-safety goals of the
ingress design.

`data_ops/` is scoped to that cold path only:

- **Airflow** — schedules/orchestrates batch jobs downstream of the S3
  archive (rollups, compaction, reporting). No involvement in real-time
  ingest.
- **Spark** — does the actual batch compute (aggregation, partition
  compaction, feature extraction) over the archived Parquet.

## Relationship to existing work

- `containers/airflow/` and `containers/spark/` (one level up from this repo)
  already contain full, working Docker/K8s/Ansible deployments of Airflow 3.3
  and Spark. **Reuse those for actual infra** when this moves past concept —
  do not re-derive cluster/deployment config here. This directory only holds
  the DAGs/jobs specific to this pipeline's data.
- `containers/airflow/telemetry_pipeline/` already has a generic
  `telemetry_etl.py` example. The draft DAG here is more specific: it targets
  the exact Hive-partitioned layout `worker_s3_archive` writes.
- `mlops/scripts/01_spool_datasets.py` already spools training data directly
  from S3/Qdrant for the model swarm. **data_ops is not a replacement for
  that** — it's for generic rollups/compaction/reporting on the raw archive.
  If this concept is promoted, `01_spool_datasets.py` should keep reading
  from S3 directly (or from Spark-produced rollup tables), not be replaced.

## Input contract (from `services/worker_s3_archive`)

```
s3://{S3_BUCKET_NAME}/telemetry/{sensor_type}/dt=YYYY-MM-DD/hour=HH/{uuid}.parquet
```

- Bucket: `S3_BUCKET_NAME` (default `nexus-cold-storage` in `nexus.env.example`)
- Endpoint: `S3_ENDPOINT` (MinIO in dev)
- Objects are Parquet with **internal ZSTD column compression** (written by
  the sensors), one object per NATS batch — i.e. many small files per
  partition. Compaction of those small files is this pipeline's job.
- `{sensor_type}` is the wire `X-Sensor-Type` value, which can differ from
  nexus.toml `[schema_mappings]` keys (`Linux-Sentinel` vs `linux_sentinel`)
  and includes a runtime-only `unclassified` fallback — which is why the DAG
  discovers partitions from S3 instead of hardcoding a sensor list.
- Objects keyed `*.parquet.zst` (opt-in `S3_COMPRESS_LEVEL > 0` deep-archive
  wrap) are **not** readable in place and are skipped by the job's
  `pathGlobFilter`, matching hunter/mlops glob behavior.

## Output contract (consumed by nothing yet — additive only)

```
s3://{bucket}/telemetry_rollup/{sensor_type}/dt=.../hour=HH/part-*.parquet   # compacted, same schema
s3://{bucket}/telemetry_rollup_stats/{sensor_type}/dt=.../part-*.parquet     # per-hour row counts
```

Interop rules baked into the job (per CODE_GRAPH.md "Stores": llm_hunter_swarm
reads the raw archive):

- raw `telemetry/` objects are never deleted or rewritten;
- rollup output reproduces the `dt=/hour=` dir shape (zero-padded hour
  preserved — partition type inference is disabled), so hunter DuckDB globs
  could later point at the compacted prefix with no query changes;
- schema passes through verbatim, so worker_qdrant/mlops identifier-column
  duck-typing still works against compacted files;
- a write-audit fails the job loudly if output rows != input rows.

## Layout

```
data_ops/
├── README.md
├── airflow/
│   └── dags/
│       └── telemetry_rollup_dag.py   # daily: discover S3 partitions -> mapped spark-submit per sensor
└── spark/
    └── jobs/
        └── telemetry_rollup.py       # compact one dt= partition + hourly stats (write-audited)
```

Unit tests: `tests/lab_data_ops/test_data_ops_contracts.py` (prefix mapping /
validation logic, DAG contracts, Dockerfile version-pin consistency) and
`tests/lab_s3_worker/test_archive_compression_contract.py` (the
`*.parquet.zst` seam this pipeline depends on).

## Build files (staged, not wired in)

`infrastructure/airflow/Dockerfile` and `infrastructure/spark/Dockerfile` exist
as **staged build files only** — they extend the same official images
`containers/airflow` and `containers/spark` use, and bake in the DAGs/jobs
above. Deliberately **not yet done**, on purpose, until this concept is
actually validated against a real bucket:

- No `airflow_node` / `spark_node` Ansible role.
- No entry in `infrastructure/ansible/site.yml` or `inventory/hosts.yml`.
- No Podman Quadlet, no host group, no `data_ops.yml` playbook (contrast
  with `det_chamber.yml`, which is a real standalone playbook — this isn't
  that yet).

Building the images is a manual, local exercise for now — see the comment
block at the top of each Dockerfile for the `cp`/`podman build` steps. Adding
the Ansible role + inventory group is future work once the concept has been
proven out (see "Next steps" below).

## Explicit non-goals (for now)

- Not a replacement for any part of the real-time ingest path.
- Not wired to a live scheduler, bucket, or Spark cluster.
- Unit-tested (contracts + pure logic) but **not live-tested** — no data has
  been run through a real MinIO/Spark stack yet.
- Not a decision to adopt Airflow/Spark; it's the scaffold needed to evaluate
  that decision with something concrete instead of on paper.

## Next steps before promotion out of "concept"

1. Point the Spark job at a real MinIO bucket in dev and validate read
   throughput against the small-file layout above. (Cadence/grain and output
   prefixes are now decided: daily runs, per-hour compaction, sibling
   `telemetry_rollup*/` prefixes — see Output contract above.)
2. Build both staged images and verify the client-mode spark-submit path
   end-to-end (`AIRFLOW_CONN_SPARK_DEFAULT`, shared network, s3a jars).
3. Wire `containers/airflow/docker-compose.yaml` to actually schedule
   `telemetry_rollup_dag.py` and confirm end-to-end on sample archive data.
4. Only then consider whether `mlops/scripts/01_spool_datasets.py` should
   read from rollup output instead of raw S3.
5. Only after 1-4 hold up: write `airflow_node` / `spark_node` Ansible roles
   and a standalone `data_ops.yml` playbook (mirroring `det_chamber.yml`,
   not folded into `site.yml`), and add a `data_ops` inventory group. Not
   before — this stays manual/local until the concept earns real
   infrastructure.

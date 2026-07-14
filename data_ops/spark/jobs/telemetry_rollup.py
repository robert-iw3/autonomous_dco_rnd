"""
data_ops v0.2 — implementation candidate, pending live validation (see
data_ops/README.md for promotion gates).

Compacts one (sensor_type, dt) partition of the telemetry archive written by
services/worker_s3_archive and emits per-hour rollup stats.

Input:
    s3a://{bucket}/telemetry/{sensor_type}/dt=YYYY-MM-DD/hour=HH/{uuid}.parquet
    (one small ZSTD Parquet file per NATS batch)

Output:
    s3a://{bucket}/telemetry_rollup/{sensor_type}/dt=YYYY-MM-DD/hour=HH/part-*.parquet
    s3a://{bucket}/telemetry_rollup_stats/{sensor_type}/dt=YYYY-MM-DD/part-*.parquet

Interoperability contract (from CODE_GRAPH.md "Stores"):

- llm_hunter_swarm reads the raw archive with DuckDB globs shaped
  `telemetry/{sensor}/dt=*/hour=*/*.parquet` (agents/supervisor.py,
  nettap_expert.py). Therefore:
    * raw files are NEVER deleted or rewritten here — output goes to a
      sibling prefix, so hunter queries keep working unchanged;
    * rollup output reproduces the exact dt=/hour= dir shape, so the hunter
      can later be pointed at the compacted prefix with zero query changes;
    * stats live under a separate top-level prefix (telemetry_rollup_stats/),
      never inside a dir a `*.parquet` glob could pick up.
- Schema is preserved verbatim (no column renames/drops): worker_qdrant and
  the mlops spool scripts type-detect sources by identifier columns from
  services/config/nexus.toml, and that detection must keep working against
  compacted files.
"""

from __future__ import annotations

import argparse
import os
import sys

# pyspark imports live inside the functions that need them so the pure
# helpers below stay importable in test environments without a Spark
# distribution (tests/lab_data_ops).

RAW_ROOT = "telemetry/"
ROLLUP_ROOT = "telemetry_rollup/"
STATS_ROOT = "telemetry_rollup_stats/"


def validate_prefix(prefix: str) -> str:
    """A rollup prefix must be one dt= partition under the raw archive root.

    Guards against accidentally pointing the job at rollup output (feedback
    loop) or at the bucket root (unbounded scan).
    """
    if not prefix.startswith(RAW_ROOT):
        raise ValueError(f"prefix must start with '{RAW_ROOT}': {prefix}")
    if "/dt=" not in prefix or not prefix.endswith("/"):
        raise ValueError(
            f"prefix must be a single 'telemetry/<sensor>/dt=<date>/' partition: {prefix}"
        )
    return prefix


def rollup_dest(prefix: str) -> str:
    """telemetry/... -> telemetry_rollup/... (first occurrence only)."""
    return prefix.replace(RAW_ROOT, ROLLUP_ROOT, 1)


def stats_dest(prefix: str) -> str:
    """telemetry/... -> telemetry_rollup_stats/... (first occurrence only)."""
    return prefix.replace(RAW_ROOT, STATS_ROOT, 1)


def build_spark_session(app_name: str = "telemetry_rollup"):
    """Session config for MinIO-compatible s3a access.

    When submitted by the Airflow DAG these confs arrive via --conf and the
    builder calls are no-ops; the env fallbacks keep standalone
    `spark-submit telemetry_rollup.py ...` runs working for local testing.
    """
    from pyspark.sql import SparkSession

    endpoint = os.environ.get("S3_ENDPOINT", "http://minio:9000")
    builder = (
        SparkSession.builder.appName(app_name)
        .config("spark.hadoop.fs.s3a.endpoint", endpoint)
        .config("spark.hadoop.fs.s3a.path.style.access", "true")
        .config(
            "spark.hadoop.fs.s3a.connection.ssl.enabled",
            str(endpoint.startswith("https")).lower(),
        )
        .config("spark.sql.parquet.compression.codec", "zstd")
        # Keep hour=05 as the string "05" — inference would parse it to int 5
        # and write the dir back as hour=5, silently changing the layout the
        # hunter globs and worker_s3_archive both use.
        .config("spark.sql.sources.partitionColumnTypeInference.enabled", "false")
    )
    return builder.getOrCreate()


def rollup_partition(spark, bucket: str, prefix: str) -> None:
    """Compact one telemetry/{sensor}/dt=D/ partition and write hourly stats."""
    from pyspark.sql import functions as F

    validate_prefix(prefix)

    src = f"s3a://{bucket}/{prefix}"
    # Reading the dt= dir lets Spark discover hour=HH as a partition column,
    # which partitionBy() below writes back as the same dir structure.
    # Only *.parquet is globbed: opt-in deep-archive objects (*.parquet.zst,
    # see worker_s3_archive S3_COMPRESS_LEVEL) are not readable in place and
    # must be skipped, matching hunter/mlops glob behavior.
    df = spark.read.option("pathGlobFilter", "*.parquet").parquet(src)
    if "hour" not in df.columns:
        raise RuntimeError(
            f"{src} did not yield an 'hour' partition column — layout drift "
            "from worker_s3_archive's telemetry/<sensor>/dt=/hour= contract?"
        )

    input_count = df.count()
    if input_count == 0:
        print(f"[rollup] {src}: empty partition, nothing to do")
        return

    dest = f"s3a://{bucket}/{rollup_dest(prefix)}"
    # repartition on the hour column -> ~1 output file per hour dir instead
    # of one file per NATS batch.
    (
        df.repartition("hour")
        .write.mode("overwrite")
        .partitionBy("hour")
        .parquet(dest)
    )

    # Write-audit: a compaction job that loses rows must fail loudly, not
    # produce a silently-short archive copy.
    output_count = spark.read.parquet(dest).count()
    if output_count != input_count:
        raise RuntimeError(
            f"write-audit failed for {dest}: read {input_count} rows, "
            f"wrote {output_count}"
        )

    stats = (
        df.groupBy("hour")
        .agg(F.count(F.lit(1)).alias("row_count"))
        .withColumn("source_prefix", F.lit(prefix))
        .orderBy("hour")
    )
    stats.coalesce(1).write.mode("overwrite").parquet(
        f"s3a://{bucket}/{stats_dest(prefix)}"
    )

    print(f"[rollup] {src}: {input_count} rows compacted -> {dest} (audit OK)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Telemetry archive rollup/compaction")
    parser.add_argument("--bucket", required=True, help="e.g. nexus-cold-storage")
    parser.add_argument(
        "--prefix", required=True, help="e.g. telemetry/sysmon_sensor/dt=2026-07-14/"
    )
    args = parser.parse_args()

    spark = build_spark_session()
    try:
        rollup_partition(spark, args.bucket, args.prefix)
    finally:
        spark.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())

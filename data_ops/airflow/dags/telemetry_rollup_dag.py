"""
data_ops v0.2 — implementation candidate, pending live validation (see
data_ops/README.md for promotion gates).

Daily compaction/rollup over the telemetry archive written by
services/worker_s3_archive:

    s3://{S3_BUCKET_NAME}/telemetry/{sensor_type}/dt=YYYY-MM-DD/hour=HH/{uuid}.parquet

Design decisions (v0.1 -> v0.2):

- Sensor types are DISCOVERED from S3 at runtime, not hardcoded. The wire
  X-Sensor-Type values that become Hive partition dirs do not always match
  the [schema_mappings.*] keys in services/config/nexus.toml (e.g.
  "Linux-Sentinel" on the wire vs "linux_sentinel" as the table key), and
  the archiver also writes an "unclassified" fallback partition. Listing
  the bucket is the only source that can't drift.

- One mapped SparkSubmitOperator per discovered (sensor_type, dt) partition
  via dynamic task mapping, so a failed sensor partition retries alone.

- Config comes from the same env contract as worker_s3_archive
  (S3_BUCKET_NAME / S3_ENDPOINT / AWS_* in nexus.env) so the two ends of
  the archive can never disagree about where the data lives.

This DAG never touches the real-time path (sensor -> core_ingress -> NATS ->
workers); it reads yesterday's closed dt= partitions only.
"""

from __future__ import annotations

import os

import pendulum
from airflow.providers.apache.spark.operators.spark_submit import SparkSubmitOperator
from airflow.sdk import DAG, task

S3_BUCKET = os.environ.get("S3_BUCKET_NAME", "nexus-cold-storage")
S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://minio:9000")
ARCHIVE_ROOT = "telemetry/"

# Client-mode submit runs the driver on THIS worker, so the job file must
# exist locally: infrastructure/airflow/Dockerfile COPYs data_ops/spark/jobs
# to this path at build time.
SPARK_JOB = "/opt/airflow/spark_jobs/telemetry_rollup.py"

with DAG(
    dag_id="telemetry_rollup",
    description="Daily compaction/rollup of the S3 telemetry archive (data_ops cold path)",
    schedule="@daily",
    start_date=pendulum.datetime(2026, 7, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
    tags=["data_ops", "cold-path"],
) as dag:

    @task
    def discover_partitions(logical_date=None) -> list[str]:
        """List telemetry/{sensor_type}/dt={ds}/ prefixes that actually exist.

        Uses boto3 directly (same S3 env contract as worker_s3_archive)
        rather than an Airflow connection, so dev and prod need exactly one
        source of S3 truth: nexus.env.
        """
        import boto3

        ds = logical_date.format("YYYY-MM-DD")
        s3 = boto3.client(
            "s3",
            endpoint_url=S3_ENDPOINT,
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        )

        # One level of CommonPrefixes = the sensor_type dirs.
        resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=ARCHIVE_ROOT, Delimiter="/")
        sensor_prefixes = [p["Prefix"] for p in resp.get("CommonPrefixes", [])]

        # Keep only sensors that produced data for this logical date.
        partitions = []
        for sensor_prefix in sensor_prefixes:
            day_prefix = f"{sensor_prefix}dt={ds}/"
            probe = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=day_prefix, MaxKeys=1)
            if probe.get("KeyCount", 0) > 0:
                partitions.append(day_prefix)
        return partitions

    @task
    def build_submit_args(partitions: list[str]) -> list[list[str]]:
        """One spark-submit arg vector per partition, for dynamic mapping.

        A named task (not XComArg.map with a lambda) so the mapping survives
        DAG serialization across Airflow 3.x minors.
        """
        return [["--bucket", S3_BUCKET, "--prefix", p] for p in partitions]

    # Client-mode submit (Spark standalone does not support cluster-mode for
    # Python apps): the driver runs inside the Airflow worker, so the worker
    # image carries pyspark + JRE (infrastructure/airflow/Dockerfile) and must
    # share a network with the Spark executors.
    rollup = SparkSubmitOperator.partial(
        task_id="rollup_partition",
        application=SPARK_JOB,
        # Provided as an env var on the Airflow container (no UI/db setup):
        #   AIRFLOW_CONN_SPARK_DEFAULT='spark://spark-master:7077'
        conn_id="spark_default",
        conf={
            # MinIO-compatible s3a wiring. Credentials are NOT set here: the
            # default s3a provider chain reads AWS_ACCESS_KEY_ID/-SECRET from
            # the driver/executor environment (nexus.env), same contract as
            # worker_s3_archive.
            "spark.hadoop.fs.s3a.endpoint": S3_ENDPOINT,
            "spark.hadoop.fs.s3a.path.style.access": "true",
            "spark.hadoop.fs.s3a.connection.ssl.enabled": str(
                S3_ENDPOINT.startswith("https")
            ).lower(),
        },
        retries=2,
    ).expand(application_args=build_submit_args(discover_partitions()))

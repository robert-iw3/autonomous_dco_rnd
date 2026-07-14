"""
Lab Data Ops: cold-path rollup contracts (data_ops v0.2).

Covers the pure logic of data_ops/spark/jobs/telemetry_rollup.py (imported
directly — its pyspark imports are deferred so no Spark install is needed)
and source-level contracts on the DAG + staged build files:

  1. Prefix mapping never touches the raw archive root and is idempotent-safe
     (rollup output can't be re-fed into the job).
  2. The DAG discovers sensors from S3 instead of hardcoding wire names
     (X-Sensor-Type values like "Linux-Sentinel" drift from config keys).
  3. The DAG's env contract matches worker_s3_archive's (nexus.env), and its
     job path matches what infrastructure/airflow/Dockerfile bakes in.
  4. Spark/pyspark versions are pinned identically across the two staged
     Dockerfiles (client-mode submit requires driver == cluster version).

Run:
    pytest tests/lab_data_ops/test_data_ops_contracts.py -v
"""
import importlib.util
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
ROLLUP_JOB = PROJECT_ROOT / "data_ops/spark/jobs/telemetry_rollup.py"
ROLLUP_DAG = PROJECT_ROOT / "data_ops/airflow/dags/telemetry_rollup_dag.py"
AIRFLOW_DOCKERFILE = PROJECT_ROOT / "infrastructure/airflow/Dockerfile"
SPARK_DOCKERFILE = PROJECT_ROOT / "infrastructure/spark/Dockerfile"


def _load_rollup_module():
    spec = importlib.util.spec_from_file_location("telemetry_rollup", ROLLUP_JOB)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def rollup():
    return _load_rollup_module()


class TestPrefixMapping:
    def test_module_imports_without_pyspark(self, rollup):
        """Deferred pyspark imports keep the pure helpers unit-testable."""
        assert rollup.RAW_ROOT == "telemetry/"

    def test_rollup_dest_maps_to_sibling_prefix(self, rollup):
        assert (
            rollup.rollup_dest("telemetry/network_tap/dt=2026-07-13/")
            == "telemetry_rollup/network_tap/dt=2026-07-13/"
        )

    def test_stats_dest_maps_to_stats_prefix(self, rollup):
        assert (
            rollup.stats_dest("telemetry/suricata_eve/dt=2026-07-13/")
            == "telemetry_rollup_stats/suricata_eve/dt=2026-07-13/"
        )

    def test_first_occurrence_only(self, rollup):
        """A sensor dir literally named 'telemetry' must not be double-mapped."""
        assert (
            rollup.rollup_dest("telemetry/telemetry/dt=2026-07-13/")
            == "telemetry_rollup/telemetry/dt=2026-07-13/"
        )

    def test_output_prefixes_never_collide_with_raw_root(self, rollup):
        """Hunter globs telemetry/** — rollup output must live outside it."""
        dest = rollup.rollup_dest("telemetry/network_tap/dt=2026-07-13/")
        stats = rollup.stats_dest("telemetry/network_tap/dt=2026-07-13/")
        for out in (dest, stats):
            assert not out.startswith(rollup.RAW_ROOT)


class TestPrefixValidation:
    def test_valid_prefix_passes(self, rollup):
        p = "telemetry/sysmon_sensor/dt=2026-07-13/"
        assert rollup.validate_prefix(p) == p

    def test_rollup_output_rejected_as_input(self, rollup):
        """Feeding rollup output back in would loop the compaction."""
        with pytest.raises(ValueError):
            rollup.validate_prefix("telemetry_rollup/sysmon_sensor/dt=2026-07-13/")

    def test_bucket_root_rejected(self, rollup):
        with pytest.raises(ValueError):
            rollup.validate_prefix("telemetry/")

    def test_sensor_dir_without_dt_partition_rejected(self, rollup):
        """A sensor-level prefix would scan the entire history unbounded."""
        with pytest.raises(ValueError):
            rollup.validate_prefix("telemetry/sysmon_sensor/")

    def test_missing_trailing_slash_rejected(self, rollup):
        with pytest.raises(ValueError):
            rollup.validate_prefix("telemetry/sysmon_sensor/dt=2026-07-13")


class TestRollupJobSource:
    def test_glob_filter_skips_wrapped_objects(self):
        """The job must read only *.parquet — *.parquet.zst deep-archive
        objects (worker_s3_archive S3_COMPRESS_LEVEL > 0) are opaque."""
        src = ROLLUP_JOB.read_text()
        assert 'option("pathGlobFilter", "*.parquet")' in src

    def test_partition_type_inference_disabled(self):
        """hour=05 must survive as the string '05', not become int 5 and be
        rewritten as hour=5 on output (layout drift vs worker_s3_archive)."""
        src = ROLLUP_JOB.read_text()
        assert "spark.sql.sources.partitionColumnTypeInference.enabled" in src

    def test_write_audit_present(self):
        """Compaction must fail loudly if output rows != input rows."""
        src = ROLLUP_JOB.read_text()
        assert "write-audit" in src and "output_count != input_count" in src


class TestDagContracts:
    def test_no_hardcoded_sensor_types(self):
        """Sensor dirs come from S3 discovery: wire X-Sensor-Type values
        (e.g. Linux-Sentinel) drift from nexus.toml schema_mappings keys, and
        'unclassified' fallback partitions exist only at runtime.

        Checks list/tuple literals in the AST (where a hardcoded sensor
        registry would live), not raw text — docstrings may legitimately
        mention wire names when explaining this exact rule."""
        import ast

        tree = ast.parse(ROLLUP_DAG.read_text())
        literal_strings = {
            el.value
            for node in ast.walk(tree)
            if isinstance(node, (ast.List, ast.Tuple, ast.Set))
            for el in node.elts
            if isinstance(el, ast.Constant) and isinstance(el.value, str)
        }
        for wire_name in ("Linux-Sentinel", "sysmon_sensor", "linux_sentinel",
                          "network_tap", "suricata_eve"):
            assert wire_name not in literal_strings, (
                f"DAG hardcodes sensor type {wire_name!r} in a collection "
                "literal; it must discover partitions from S3 instead"
            )

    def test_env_contract_matches_worker_s3_archive(self):
        """Both ends of the archive read the same nexus.env variables."""
        src = ROLLUP_DAG.read_text()
        for var in ("S3_BUCKET_NAME", "S3_ENDPOINT", "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY"):
            assert var in src, f"DAG missing env var {var} from the S3 contract"

    def test_dag_guardrails(self):
        src = ROLLUP_DAG.read_text()
        assert "catchup=False" in src
        assert "max_active_runs=1" in src

    def test_no_lambda_in_dynamic_mapping(self):
        """XComArg.map(lambda) does not survive DAG serialization on all
        Airflow 3.x minors; mapping must go through a named @task."""
        src = ROLLUP_DAG.read_text()
        assert ".map(" not in src
        assert "build_submit_args" in src

    def test_job_path_matches_airflow_dockerfile(self):
        """Client-mode submit needs the job file on the Airflow worker at the
        exact path the DAG references."""
        dag_src = ROLLUP_DAG.read_text()
        m = re.search(r'SPARK_JOB = "([^"]+)"', dag_src)
        assert m, "SPARK_JOB constant missing from DAG"
        job_path = m.group(1)
        assert job_path.startswith("/opt/airflow/spark_jobs/")

        docker_src = AIRFLOW_DOCKERFILE.read_text()
        assert "/opt/airflow/spark_jobs" in docker_src, (
            "infrastructure/airflow/Dockerfile must COPY the spark jobs to "
            "the path the DAG submits from"
        )


class TestStagedBuildFiles:
    @staticmethod
    def _arg(dockerfile: Path, name: str) -> str:
        m = re.search(rf"ARG {name}=([\w.]+)", dockerfile.read_text())
        assert m, f"{dockerfile.name} missing ARG {name}"
        return m.group(1)

    def test_spark_version_pinned_identically(self):
        """pyspark driver (Airflow image) and cluster (Spark image) must run
        the same Spark version — client mode fails on mismatch."""
        airflow_pin = self._arg(AIRFLOW_DOCKERFILE, "SPARK_VERSION")
        spark_pin = self._arg(SPARK_DOCKERFILE, "SPARK_VERSION")
        assert airflow_pin == spark_pin

    def test_spark_image_bakes_s3a_jars(self):
        """The stock apache/spark image has no s3a filesystem; the staged
        build must ADD hadoop-aws + AWS SDK bundle (not --packages, which
        breaks air-gapped runs)."""
        src = SPARK_DOCKERFILE.read_text()
        assert "hadoop-aws" in src
        assert "software/amazon/awssdk/bundle" in src
        instructions = "\n".join(
            line for line in src.splitlines() if not line.lstrip().startswith("#")
        )
        assert "--packages" not in instructions

    def test_not_wired_into_ansible(self):
        """data_ops stays out of the deploy plane until promoted: no role,
        no site.yml entry (data_ops/README.md promotion gates)."""
        roles = PROJECT_ROOT / "infrastructure/ansible/roles"
        assert not (roles / "airflow_node").exists()
        assert not (roles / "spark_node").exists()
        site = (PROJECT_ROOT / "infrastructure/ansible/site.yml").read_text()
        assert "data_ops" not in site

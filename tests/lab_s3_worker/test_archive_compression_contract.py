"""
Lab S3 Worker: archive compression contract (QA F1).

worker_s3_archive must store objects that are queryable IN PLACE by every
archive consumer (llm_hunter DuckDB globs, mlops pyarrow spool, data_ops
Spark). A whole-file ZSTD wrap breaks all of them, so the contract is:

  1. S3_COMPRESS_LEVEL defaults to 0 (no wrap) — parquet is already ZSTD
     column-compressed by the sensors.
  2. When the wrap is explicitly enabled, the object key gets a
     ".parquet.zst" suffix so `*.parquet` globs skip the opaque object
     instead of failing mid-scan.
  3. The source no longer claims DuckDB reads wrapped files transparently
     (it can't: read_parquet needs PAR1 magic + footer seeks).

Source-assertion style follows tests/lab_infra_contracts.

Run:
    pytest tests/lab_s3_worker/test_archive_compression_contract.py -v
"""
import io
import re
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
WORKER_MAIN = PROJECT_ROOT / "services/worker_s3_archive/src/main.rs"
ENV_EXAMPLE = PROJECT_ROOT / "nexus.env.example"


def _src() -> str:
    return WORKER_MAIN.read_text()


class TestCompressLevelDefault:
    def test_compress_level_defaults_to_zero(self):
        """S3_COMPRESS_LEVEL absent -> no whole-file wrap (contract #1)."""
        m = re.search(
            r'S3_COMPRESS_LEVEL"\)\s*\.ok\(\)\.and_then\(\|v\| v\.parse\(\)\.ok\(\)\)'
            r"\.unwrap_or\((\d+)\)",
            _src(),
        )
        assert m, "S3_COMPRESS_LEVEL parse/default expression not found in main.rs"
        assert m.group(1) == "0", (
            f"S3_COMPRESS_LEVEL must default to 0 (got {m.group(1)}): a non-zero "
            "default zstd-wraps archive objects and breaks every in-place reader"
        )

    def test_env_example_documents_compress_level(self):
        env = ENV_EXAMPLE.read_text()
        assert "S3_COMPRESS_LEVEL=0" in env, (
            "nexus.env.example must pin S3_COMPRESS_LEVEL=0 and document the "
            "queryability trade-off"
        )


class TestWrappedObjectSuffix:
    def test_wrapped_objects_use_zst_suffix(self):
        """Enabled wrap -> *.parquet.zst keys (contract #2)."""
        assert '"parquet.zst"' in _src(), (
            "wrapped uploads must be keyed *.parquet.zst so *.parquet globs "
            "skip them"
        )

    def test_object_key_extension_is_dynamic(self):
        """The key format must take the extension from the compression branch,
        not hardcode .parquet for all uploads."""
        src = _src()
        assert re.search(r'"telemetry/\{\}/dt=\{\}/hour=\{\}/\{\}\.\{\}"', src), (
            "object_key format must end in {}.{} (uuid + branch-selected "
            "extension)"
        )
        assert not re.search(r'"telemetry/\{\}/dt=\{\}/hour=\{\}/\{\}\.parquet"', src), (
            "found a hardcoded .parquet object key — wrapped objects would be "
            "mislabeled as readable parquet"
        )

    def test_misleading_duckdb_claim_removed(self):
        """The old comment asserted DuckDB transparently decompresses whole-file
        zstd parquet; it does not (contract #3)."""
        assert "decompresses transparently" not in _src()


class TestWhyTheSuffixMatters:
    """Behavioral proof (pure Python) that a zstd-wrapped parquet file is
    unreadable in place — documents the failure mode the suffix prevents."""

    @staticmethod
    def _tiny_parquet() -> bytes:
        table = pa.table({"anomaly_score": [0.1, 0.9], "timestamp_epoch": [1, 2]})
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        return buf.getvalue()

    def test_internal_zstd_parquet_reads_fine(self):
        raw = self._tiny_parquet()
        assert raw[:4] == b"PAR1", "parquet magic missing"
        assert pq.read_table(io.BytesIO(raw)).num_rows == 2

    def test_whole_file_zstd_wrap_is_unreadable(self):
        raw = self._tiny_parquet()
        wrapped = pa.compress(raw, codec="zstd", asbytes=True)
        assert wrapped[:4] != b"PAR1", "wrap should destroy the parquet magic"
        with pytest.raises(Exception):
            pq.read_table(io.BytesIO(wrapped))

    def test_parquet_glob_skips_zst_suffix(self):
        """The exact glob the hunter/mlops/data_ops readers use must not match
        a wrapped key."""
        import fnmatch

        wrapped_key = "telemetry/network_tap/dt=2026-07-13/hour=05/abc.parquet.zst"
        plain_key = "telemetry/network_tap/dt=2026-07-13/hour=05/abc.parquet"
        assert not fnmatch.fnmatch(wrapped_key, "telemetry/*/dt=*/hour=*/*.parquet")
        assert fnmatch.fnmatch(plain_key, "telemetry/*/dt=*/hour=*/*.parquet")

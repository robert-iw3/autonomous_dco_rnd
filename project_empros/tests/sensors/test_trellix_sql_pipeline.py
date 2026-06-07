"""
test_trellix_sql_pipeline.py -- Static validation of the Trellix ENS SQL pipeline.

Coverage:
  SQL init scripts          -- schema correctness, required objects, watermark seeding
  SP_Sync_ENSEvents         -- incremental watermark pattern, pre-sync test block
  SP_Sync_AppControlEvents  -- AppControl filter, separate watermark row
  UEBA engine               -- entropy, frequency, anomaly_score, IsolationForest refit
  Parquet schema            -- 6D vector, field types, row construction
  Reader source analysis    -- HMAC signing, stream classification, env vars
  Config files              -- docker-compose env vars, config.json schema, nexus.toml 6D
  Qdrant init               -- trellix_math size=6 in qdrant_init.sh
  Worker Qdrant Rust        -- 6D clamp path exists in main.rs
"""

import hashlib
import hmac
import importlib.util
import io
import json
import re
import sys
import tempfile
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO        = Path(__file__).parent.parent.parent       # project_empros/
ROOT        = REPO.parent

TRELLIX_SQL  = ROOT / "windows" / "trellix_sql"
TRELLIX_OLD  = ROOT / "windows" / "trellix_endpoint"
TRANSMIT     = TRELLIX_SQL / "transmit"
SQL_DIR      = TRELLIX_SQL / "sql"

SERVICES_CFG = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG    = REPO / "tests"    / "config" / "nexus.toml"
QDRANT_SH    = REPO / "tests"    / "deploy" / "config" / "qdrant_init.sh"
WORKER_RUST  = REPO / "services" / "worker_qdrant" / "src" / "main.rs"


# ── sklearn stub for UEBA import ──────────────────────────────────────────────

def _ensure_sklearn_stub():
    if "sklearn" not in sys.modules:
        import types
        import numpy as np

        sklearn_mod   = types.ModuleType("sklearn")
        ensemble_mod  = types.ModuleType("sklearn.ensemble")

        class _FakeIsolationForest:
            def __init__(self, **kw): self._fitted = False
            def fit(self, X): self._fitted = True; return self
            def score_samples(self, X):
                return np.full(len(X), -0.25)

        ensemble_mod.IsolationForest = _FakeIsolationForest
        sklearn_mod.ensemble = ensemble_mod
        sys.modules["sklearn"] = sklearn_mod
        sys.modules["sklearn.ensemble"] = ensemble_mod


def _load_module(path: Path, name: str):
    _ensure_sklearn_stub()
    if str(TRANSMIT) not in sys.path:
        sys.path.insert(0, str(TRANSMIT))
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ══════════════════════════════════════════════════════════════════════════════
# Archive
# ══════════════════════════════════════════════════════════════════════════════

class TestArchive:

    def test_trellix_archived_notice_exists(self):
        assert (TRELLIX_OLD / "ARCHIVED.md").exists(), \
            "windows/trellix_endpoint/ARCHIVED.md missing -- legacy endpoint sensor must be archived"

    def test_archived_notice_references_replacement(self):
        src = (TRELLIX_OLD / "ARCHIVED.md").read_text()
        assert "trellix_sql" in src.lower() or "sql" in src.lower()

    def test_archived_notice_explains_reason(self):
        assert len((TRELLIX_OLD / "ARCHIVED.md").read_text()) > 30


# ══════════════════════════════════════════════════════════════════════════════
# SQL scripts
# ══════════════════════════════════════════════════════════════════════════════

class TestSQLScripts:

    def test_init_db_exists(self):
        assert (SQL_DIR / "01_init_db.sql").exists()

    def test_sp_sync_ens_exists(self):
        assert (SQL_DIR / "02_sp_sync_ens.sql").exists()

    def test_sp_sync_appcontrol_exists(self):
        assert (SQL_DIR / "03_sp_sync_appcontrol.sql").exists()

    def test_tuning_exists(self):
        assert (SQL_DIR / "04_tuning.sql").exists()

    def test_entrypoint_exists(self):
        assert (SQL_DIR / "00_entrypoint.sh").exists()

    def test_init_creates_consolidated_db(self):
        assert "ConsolidatedEventsENS" in (SQL_DIR / "01_init_db.sql").read_text()

    def test_init_creates_epoevents_table(self):
        assert "EPOEvents_Consolidated" in (SQL_DIR / "01_init_db.sql").read_text()

    def test_init_creates_syncwatermark_table(self):
        assert "SyncWatermark" in (SQL_DIR / "01_init_db.sql").read_text()

    def test_init_creates_transmit_watermark(self):
        assert "TransmitWatermark" in (SQL_DIR / "01_init_db.sql").read_text()

    def test_init_seeds_ens_watermark(self):
        src = (SQL_DIR / "01_init_db.sql").read_text()
        assert "N'EPOEvents'" in src or "'EPOEvents'" in src

    def test_init_seeds_appcontrol_watermark(self):
        src = (SQL_DIR / "01_init_db.sql").read_text()
        assert "N'AppControl'" in src or "'AppControl'" in src

    def test_init_creates_appcontrol_view(self):
        assert "vw_AppControl_Events" in (SQL_DIR / "01_init_db.sql").read_text()

    def test_init_sets_simple_recovery(self):
        assert "SIMPLE" in (SQL_DIR / "01_init_db.sql").read_text()

    def test_init_autoid_column_defined(self):
        assert "AutoID" in (SQL_DIR / "01_init_db.sql").read_text()

    def test_init_threatseverity_column_defined(self):
        assert "ThreatSeverity" in (SQL_DIR / "01_init_db.sql").read_text()

    def test_init_canonical_epo_column_names(self):
        src = (SQL_DIR / "01_init_db.sql").read_text()
        assert "ThreatFileName"          in src, "Missing ePO-canonical ThreatFileName"
        assert "ThreatEventID"           in src, "Missing ePO-canonical ThreatEventID"
        assert "ThreatSourceUrl"         in src, "Missing ThreatSourceUrl"
        assert "AnalyzerDetectionMethod" in src, "Missing AnalyzerDetectionMethod"

    def test_init_no_legacy_nonstandard_columns(self):
        # Strip inline comments before checking column names
        src_no_comments = re.sub(r'--[^\n]*', '', (SQL_DIR / "01_init_db.sql").read_text())
        assert "PointProduct"     not in src_no_comments, \
            "PointProduct is not a real ePO column (use AnalyzerName)"
        assert "EventDescription" not in src_no_comments, \
            "EventDescription is not a standard ePO column"
        assert not re.search(r'\bFilePath\b', src_no_comments), \
            "FilePath is non-standard; should be ThreatFileName"
        assert not re.search(r'(?<![A-Za-z])EventID\b', src_no_comments), \
            "Bare EventID is non-standard; should be ThreatEventID"

    def test_sp_sync_ens_uses_watermark_pattern(self):
        src = (SQL_DIR / "02_sp_sync_ens.sql").read_text()
        assert "LastSyncedAutoID" in src
        assert "ORDER BY" in src

    def test_sp_sync_ens_batching_uses_top(self):
        assert "SELECT TOP" in (SQL_DIR / "02_sp_sync_ens.sql").read_text()

    def test_sp_sync_ens_presync_test(self):
        src = (SQL_DIR / "02_sp_sync_ens.sql").read_text()
        assert "PRE_SYNC_TEST" in src or "connectivity" in src.lower()

    def test_sp_sync_ens_identity_insert(self):
        assert "IDENTITY_INSERT" in (SQL_DIR / "02_sp_sync_ens.sql").read_text()

    def test_sp_sync_ens_try_catch(self):
        src = (SQL_DIR / "02_sp_sync_ens.sql").read_text()
        assert "BEGIN TRY" in src and "BEGIN CATCH" in src

    def test_appcontrol_filter_event_id_range(self):
        src = (SQL_DIR / "03_sp_sync_appcontrol.sql").read_text()
        assert "34000" in src and "34999" in src

    def test_appcontrol_uses_threateventid_canonical(self):
        src = (SQL_DIR / "03_sp_sync_appcontrol.sql").read_text()
        assert "ThreatEventID" in src, \
            "AppControl SP must filter on ThreatEventID (ePO canonical), not bare EventID"

    def test_appcontrol_separate_watermark_key(self):
        assert "AppControl" in (SQL_DIR / "03_sp_sync_appcontrol.sql").read_text()

    def test_tuning_maxdop_one(self):
        src = (SQL_DIR / "04_tuning.sql").read_text().lower()
        assert "max degree of parallelism" in src and "1" in src

    def test_tuning_rcsi(self):
        assert "READ_COMMITTED_SNAPSHOT" in (SQL_DIR / "04_tuning.sql").read_text()

    def test_entrypoint_waits_for_sql_ready(self):
        src = (SQL_DIR / "00_entrypoint.sh").read_text()
        assert "MAX_ATTEMPTS" in src or "retry" in src.lower() or "sleep" in src.lower()

    def test_entrypoint_configures_linked_server(self):
        src = (SQL_DIR / "00_entrypoint.sh").read_text()
        assert "EPO_PRODUCTION" in src or "linked" in src.lower()


# ══════════════════════════════════════════════════════════════════════════════
# Dockerfiles & compose
# ══════════════════════════════════════════════════════════════════════════════

class TestDockerfiles:

    def test_dockerfile_2022_exists(self):
        assert (TRELLIX_SQL / "Dockerfile.mssql2022").exists()

    def test_dockerfile_2025_exists(self):
        assert (TRELLIX_SQL / "Dockerfile.mssql2025").exists()

    def test_docker_compose_exists(self):
        assert (TRELLIX_SQL / "docker-compose.yml").exists()

    def test_2022_from_mssql2022(self):
        src = (TRELLIX_SQL / "Dockerfile.mssql2022").read_text()
        assert "mcr.microsoft.com/mssql/server:2022" in src

    def test_2025_from_mssql2025(self):
        src = (TRELLIX_SQL / "Dockerfile.mssql2025").read_text()
        assert "mcr.microsoft.com/mssql/server:2025" in src

    def test_compose_defines_staging_2022_service(self):
        src = (TRELLIX_SQL / "docker-compose.yml").read_text()
        assert "staging-2022" in src or "mssql2022" in src

    def test_compose_defines_staging_2025_service(self):
        src = (TRELLIX_SQL / "docker-compose.yml").read_text()
        assert "staging-2025" in src or "mssql2025" in src

    def test_compose_defines_transmit_service(self):
        assert "transmit" in (TRELLIX_SQL / "docker-compose.yml").read_text()

    def test_compose_uses_profiles(self):
        assert "profiles" in (TRELLIX_SQL / "docker-compose.yml").read_text()

    def test_compose_internal_network(self):
        assert "internal" in (TRELLIX_SQL / "docker-compose.yml").read_text()

    def test_compose_hmac_env_var(self):
        assert "NEXUS_HMAC_SECRET" in (TRELLIX_SQL / "docker-compose.yml").read_text()

    def test_compose_no_external_egress_env(self):
        assert "TRANSFORMERS_OFFLINE" in (TRELLIX_SQL / "docker-compose.yml").read_text()

    def test_transmit_dockerfile_exists(self):
        assert (TRANSMIT / "Dockerfile").exists()

    def test_transmit_dockerfile_nonroot_user(self):
        src = (TRANSMIT / "Dockerfile").read_text()
        assert "USER" in src or "useradd" in src or "adduser" in src


# ══════════════════════════════════════════════════════════════════════════════
# UEBA engine
# ══════════════════════════════════════════════════════════════════════════════

class TestUEBAEngine:

    def _load(self):
        return _load_module(TRANSMIT / "ueba_engine.py", f"ueba_{id(self)}")

    def test_module_loads(self):
        assert self._load() is not None

    def test_shannon_entropy_empty_string(self):
        assert self._load()._shannon_entropy("") == 0.0

    def test_shannon_entropy_uniform_string(self):
        e = self._load()._shannon_entropy("aaaa")
        assert e == 0.0

    def test_shannon_entropy_four_distinct_chars(self):
        e = self._load()._shannon_entropy("abcd")
        assert e == pytest.approx(2.0, abs=1e-9)

    def test_shannon_entropy_bounded(self):
        mod = self._load()
        for s in ["hello world", r"C:\Windows\Temp\evil.exe", "a" * 100]:
            assert mod._shannon_entropy(s) >= 0.0

    def test_severity_to_float_none(self):
        assert self._load()._severity_to_float(None) == 0.0

    def test_severity_to_float_max(self):
        assert self._load()._severity_to_float(5) == pytest.approx(1.0)

    def test_severity_to_float_min(self):
        assert self._load()._severity_to_float(1) == pytest.approx(0.2)

    def test_action_to_float_blocked(self):
        assert self._load()._action_to_float("Blocked") == pytest.approx(1.0)

    def test_action_to_float_quarantined(self):
        assert self._load()._action_to_float("Quarantined") == pytest.approx(0.75)

    def test_action_to_float_none(self):
        assert self._load()._action_to_float(None) == 0.0

    def test_normalise_threat_key_strips_guid(self):
        mod = self._load()
        # Full 8-4-4-4-12 GUID suffix should be stripped by _STRIP_RE
        k1 = mod._normalise_threat_key(
            "Trojan.GenericKD.{12345678-1234-1234-1234-123456789abc}", "Trojan")
        k2 = mod._normalise_threat_key("Trojan.GenericKD.", "Trojan")
        assert k1 == k2

    def test_ueba_engine_init(self):
        with tempfile.TemporaryDirectory() as td:
            mod = self._load()
            eng = mod.TrellixUEBAEngine(db_path=Path(td) / "state.db")
            assert eng is not None

    def test_ueba_engine_score_returns_three_floats(self):
        with tempfile.TemporaryDirectory() as td:
            mod = self._load()
            eng = mod.TrellixUEBAEngine(db_path=Path(td) / "state.db")
            a, e, f = eng.score_event(
                "Trojan.GenericKD", "Trojan",
                r"C:\Windows\Temp\evil.exe", "svchost.exe", 4, "Blocked")
            assert all(isinstance(x, float) for x in (a, e, f))

    def test_ueba_engine_entropy_score_in_unit_interval(self):
        with tempfile.TemporaryDirectory() as td:
            mod = self._load()
            eng = mod.TrellixUEBAEngine(db_path=Path(td) / "state.db")
            _, e, _ = eng.score_event(
                None, None, r"C:\Windows\System32\svchost.exe", "svchost.exe", 1, "Detected")
            assert 0.0 <= e <= 1.0

    def test_ueba_engine_novel_threat_scores_higher_frequency(self):
        """After seeding with 50 diverse threats, a new unseen threat scores higher than a common one."""
        with tempfile.TemporaryDirectory() as td:
            mod = self._load()
            eng = mod.TrellixUEBAEngine(db_path=Path(td) / "state.db")
            for i in range(50):
                eng.score_event(f"Threat.{i}", "Adware",
                                 r"C:\file.exe", "svchost.exe", 1, "Detected")
            for _ in range(30):
                eng.score_event("Adware.Generic", "Adware",
                                 r"C:\file.exe", "svchost.exe", 1, "Detected")
            _, _, f_common = eng.score_event(
                "Adware.Generic", "Adware", r"C:\file.exe", "svchost.exe", 1, "Detected")
            _, _, f_novel = eng.score_event(
                "BrandNewAPT_XYZ_NeverSeen", "Exploit",
                r"C:\malware.exe", "evil.exe", 5, "Blocked")
            assert f_novel > f_common

    def test_ueba_engine_frequency_decreases_with_repetition(self):
        with tempfile.TemporaryDirectory() as td:
            mod = self._load()
            eng = mod.TrellixUEBAEngine(db_path=Path(td) / "state.db")
            for i in range(50):
                eng.score_event(f"Noise.{i}", "Adware", r"C:\f.exe", "x.exe", 1, "Detected")
            _, _, f_first = eng.score_event(
                "RealMalware.X", "Trojan", r"C:\bad.exe", "bad.exe", 5, "Blocked")
            for _ in range(30):
                eng.score_event(
                    "RealMalware.X", "Trojan", r"C:\bad.exe", "bad.exe", 5, "Blocked")
            _, _, f_later = eng.score_event(
                "RealMalware.X", "Trojan", r"C:\bad.exe", "bad.exe", 5, "Blocked")
            assert f_later < f_first

    def test_ueba_engine_refit_triggers(self):
        with tempfile.TemporaryDirectory() as td:
            mod = self._load()
            eng = mod.TrellixUEBAEngine(db_path=Path(td) / "state.db", refit_interval=10)
            for i in range(11):
                eng.score_event(f"T{i}", "Trojan", r"C:\f.exe", "bad.exe", 3, "Blocked")
            assert eng._clf_fitted

    def test_ueba_engine_anomaly_score_in_unit_interval_post_fit(self):
        with tempfile.TemporaryDirectory() as td:
            mod = self._load()
            eng = mod.TrellixUEBAEngine(db_path=Path(td) / "state.db", refit_interval=10)
            for i in range(11):
                eng.score_event(f"T{i}", "Trojan", r"C:\f.exe", "s.exe", 3, "Blocked")
            a, _, _ = eng.score_event(
                "Exploit.CVE", "Exploit", r"C:\bad.exe", "evil.exe", 5, "Blocked")
            assert 0.0 <= a <= 1.0

    def test_ueba_engine_flush_persists_to_db(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            mod = self._load()
            eng = mod.TrellixUEBAEngine(db_path=db)
            eng.score_event("Trojan.X", "Trojan", None, None, 3, "Blocked")
            eng.flush()
            assert db.exists()


# ══════════════════════════════════════════════════════════════════════════════
# Parquet schema
# ══════════════════════════════════════════════════════════════════════════════

class TestParquetSchema:

    def _load(self):
        return _load_module(TRANSMIT / "schema.py", f"schema_{id(self)}")

    def test_schema_module_loads(self):
        assert self._load() is not None

    def test_trellix_math_field_is_float32_list(self):
        mod = self._load()
        vec_field = next(f for f in mod.TRELLIX_MATH_SCHEMA if f.name == "trellix_math")
        assert pa.types.is_list(vec_field.type)
        assert vec_field.type.value_type == pa.float32()

    def test_schema_has_all_six_scalar_fields(self):
        names = [f.name for f in self._load().TRELLIX_MATH_SCHEMA]
        for field in ("severity_score", "threat_score", "action_score",
                      "anomaly_score", "entropy_score", "frequency_score"):
            assert field in names, f"Missing scalar score field: {field}"

    def test_schema_has_auto_id(self):
        names = [f.name for f in self._load().TRELLIX_MATH_SCHEMA]
        assert "auto_id" in names

    def test_schema_has_new_epo_context_columns(self):
        names = [f.name for f in self._load().TRELLIX_MATH_SCHEMA]
        for col in ("threat_source_url", "threat_category", "event_id",
                    "analyzer_detection_method", "source_component"):
            assert col in names, f"Missing ePO context column: {col}"

    def test_schema_has_file_path_mapped_from_threatfilename(self):
        names = [f.name for f in self._load().TRELLIX_MATH_SCHEMA]
        assert "file_path" in names, "file_path (mapped from ThreatFileName) missing"

    def test_schema_no_legacy_columns(self):
        names = [f.name for f in self._load().TRELLIX_MATH_SCHEMA]
        assert "point_product" not in names, "point_product is not a real ePO column"

    def test_schema_has_stream_classification_field(self):
        assert "stream" in [f.name for f in self._load().TRELLIX_MATH_SCHEMA]

    def test_build_row_produces_six_element_vector(self):
        import datetime
        mod = self._load()
        row = mod.build_row(
            auto_id=12345,
            received_utc=datetime.datetime(2026, 6, 5, 12, 0, 0),
            agent_guid="AGENT-GUID-001",
            source_host="WORKSTATION-01",
            threat_name="Trojan.GenericKD",
            threat_type="Trojan",
            threat_category="Malware",
            threat_severity=4,
            action_taken="Blocked",
            user_name="domain\\jdoe",
            threat_file_name=r"C:\Windows\Temp\evil.exe",
            threat_source_url="http://evil.example.com/evil.exe",
            process_name="evil.exe",
            threat_event_id=1092,
            analyzer_name="Endpoint Security",
            analyzer_detection_method="OAS",
            anomaly_score=0.72,
            entropy_score=0.45,
            frequency_score=0.88,
            batch_id="test-batch-001",
            stream="ens",
            severity_score=0.8,
            threat_score=1.0,
            action_score=1.0,
        )
        assert len(row["trellix_math"]) == 6

    def test_build_row_vector_order_matches_schema(self):
        """Vector[0..5] must be severity, threat, action, anomaly, entropy, frequency."""
        import datetime
        mod = self._load()
        row = mod.build_row(
            auto_id=1, received_utc=datetime.datetime.now(),
            agent_guid=None, source_host="H1",
            threat_name="X", threat_type="Trojan", threat_category=None,
            threat_severity=5, action_taken="Blocked", user_name=None,
            threat_file_name=None, threat_source_url=None,
            process_name=None, threat_event_id=None,
            analyzer_name=None, analyzer_detection_method=None,
            anomaly_score=0.3, entropy_score=0.5, frequency_score=0.7,
            batch_id="b", stream="ens",
            severity_score=1.0, threat_score=0.9, action_score=0.8,
        )
        vec = row["trellix_math"]
        assert vec[0] == pytest.approx(1.0), "vec[0] should be severity_score"
        assert vec[1] == pytest.approx(0.9), "vec[1] should be threat_score"
        assert vec[2] == pytest.approx(0.8), "vec[2] should be action_score"
        assert vec[3] == pytest.approx(0.3), "vec[3] should be anomaly_score"
        assert vec[4] == pytest.approx(0.5), "vec[4] should be entropy_score"
        assert vec[5] == pytest.approx(0.7), "vec[5] should be frequency_score"

    def test_build_row_maps_threat_file_name_to_file_path(self):
        import datetime
        mod = self._load()
        row = mod.build_row(
            auto_id=1, received_utc=datetime.datetime.now(),
            agent_guid="A", source_host="H",
            threat_name="T", threat_type="T", threat_category=None,
            threat_severity=1, action_taken="Detected", user_name=None,
            threat_file_name=r"C:\Windows\Temp\bad.exe",
            threat_source_url=None, process_name=None, threat_event_id=None,
            analyzer_name=None, analyzer_detection_method=None,
            anomaly_score=0.0, entropy_score=0.0, frequency_score=0.0,
            batch_id="b", stream="ens",
            severity_score=0.2, threat_score=0.5, action_score=0.25,
        )
        assert row["file_path"] == r"C:\Windows\Temp\bad.exe"
        assert row["file_name"] == "bad.exe"

    def test_build_row_maps_threat_event_id_to_event_id(self):
        import datetime
        mod = self._load()
        row = mod.build_row(
            auto_id=1, received_utc=datetime.datetime.now(),
            agent_guid="A", source_host="H",
            threat_name="T", threat_type="T", threat_category=None,
            threat_severity=1, action_taken="Detected", user_name=None,
            threat_file_name=None, threat_source_url=None,
            process_name=None, threat_event_id=1092,
            analyzer_name=None, analyzer_detection_method=None,
            anomaly_score=0.0, entropy_score=0.0, frequency_score=0.0,
            batch_id="b", stream="ens",
            severity_score=0.2, threat_score=0.5, action_score=0.25,
        )
        assert row["event_id"] == 1092

    def test_threat_type_to_score_trojan(self):
        assert self._load().threat_type_to_score("Trojan") == pytest.approx(1.0)

    def test_threat_type_to_score_pua(self):
        assert self._load().threat_type_to_score("PUA") == pytest.approx(0.4)

    def test_threat_type_to_score_none_returns_midpoint(self):
        assert self._load().threat_type_to_score(None) == pytest.approx(0.5)

    def test_parquet_roundtrip_all_fields_preserved(self):
        import datetime
        mod = self._load()
        row = mod.build_row(
            auto_id=99,
            received_utc=datetime.datetime(2026, 6, 5, 12, 0, 0),
            agent_guid="AGENT-1",
            source_host="HOST-A",
            threat_name="Trojan.Ransom",
            threat_type="Ransomware",
            threat_category="Malware",
            threat_severity=5,
            action_taken="Blocked",
            user_name="DOMAIN\\admin",
            threat_file_name=r"C:\bad.exe",
            threat_source_url="http://evil.example.com/bad.exe",
            process_name="bad.exe",
            threat_event_id=1805,
            analyzer_name="ENS AM",
            analyzer_detection_method="ODS",
            anomaly_score=0.85,
            entropy_score=0.62,
            frequency_score=0.90,
            batch_id="b-99",
            stream="ens",
            severity_score=1.0,
            threat_score=1.0,
            action_score=1.0,
        )
        schema = mod.TRELLIX_MATH_SCHEMA
        arrays = []
        for field in schema:
            val = [row.get(field.name)]
            if field.name == "trellix_math":
                arrays.append(pa.array(val, type=pa.list_(pa.float32())))
            else:
                arrays.append(pa.array(val, type=field.type))
        table = pa.table(
            {f.name: arrays[i] for i, f in enumerate(schema)},
            schema=schema,
        )
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        table2 = pq.read_table(buf)
        assert table2.num_rows == 1
        assert len(table2.column("trellix_math")[0].as_py()) == 6
        assert table2.column("event_id")[0].as_py() == 1805
        assert table2.column("threat_source_url")[0].as_py() == "http://evil.example.com/bad.exe"
        assert table2.column("analyzer_detection_method")[0].as_py() == "ODS"


# ══════════════════════════════════════════════════════════════════════════════
# HMAC signing logic
# ══════════════════════════════════════════════════════════════════════════════

class TestHMACSigningLogic:

    def test_hmac_sha256_signature_is_64_hex_chars(self):
        sig = hmac.new(b"secret", b"payload", hashlib.sha256).hexdigest()
        assert len(sig) == 64

    def test_hmac_signature_changes_with_payload(self):
        s1 = hmac.new(b"k", b"payload1", hashlib.sha256).hexdigest()
        s2 = hmac.new(b"k", b"payload2", hashlib.sha256).hexdigest()
        assert s1 != s2

    def test_hmac_signature_changes_with_key(self):
        s1 = hmac.new(b"k1", b"data", hashlib.sha256).hexdigest()
        s2 = hmac.new(b"k2", b"data", hashlib.sha256).hexdigest()
        assert s1 != s2

    def test_hmac_verification_passes_with_correct_key(self):
        payload = b"test parquet payload"
        secret  = b"test-hmac-secret"
        sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(sig, expected)

    def test_hmac_verification_fails_on_tampered_payload(self):
        secret   = b"test-hmac-secret"
        original = hmac.new(secret, b"original", hashlib.sha256).hexdigest()
        tampered = hmac.new(secret, b"tampered", hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(original, tampered)


# ══════════════════════════════════════════════════════════════════════════════
# Reader source static analysis
# ══════════════════════════════════════════════════════════════════════════════

class TestReaderSource:

    def _src(self):
        return (TRANSMIT / "reader.py").read_text()

    def test_reader_exists(self):
        assert (TRANSMIT / "reader.py").exists()

    def test_reader_handles_ens_stream(self):
        assert '"ens"' in self._src() or "'ens'" in self._src()

    def test_reader_handles_appcontrol_stream(self):
        assert '"appcontrol"' in self._src() or "'appcontrol'" in self._src()

    def test_reader_uses_hmac_sha256(self):
        src = self._src()
        assert "hmac" in src and "sha256" in src

    def test_reader_posts_to_nexus(self):
        assert "requests.post" in self._src()

    def test_reader_uses_transmit_watermark(self):
        assert "TransmitWatermark" in self._src()

    def test_reader_uses_ueba_engine(self):
        assert "TrellixUEBAEngine" in self._src()

    def test_reader_converts_to_parquet(self):
        assert "parquet" in self._src().lower()

    def test_reader_handles_sigterm(self):
        assert "SIGTERM" in self._src()

    def test_reader_reads_credentials_from_env(self):
        src = self._src()
        assert 'os.environ["MSSQL_PASSWORD"]' in src or "os.environ.get" in src

    def test_reader_no_hardcoded_passwords(self):
        src = self._src()
        assert not re.search(r'(?i)password\s*=\s*["\'][^"\'${\s]', src), \
            "Hardcoded password detected in reader.py"

    def test_config_json_exists(self):
        assert (TRANSMIT / "config.json").exists()

    def test_config_json_vector_dimensions_6(self):
        cfg = json.loads((TRANSMIT / "config.json").read_text())
        assert cfg["schema"]["vector_dimensions"] == 6

    def test_config_json_streams_include_ens_and_appcontrol(self):
        cfg = json.loads((TRANSMIT / "config.json").read_text())
        streams = cfg["transmission"]["streams"]
        assert "ens" in streams
        assert "appcontrol" in streams


# ══════════════════════════════════════════════════════════════════════════════
# Nexus config -- 6D trellix_math
# ══════════════════════════════════════════════════════════════════════════════

class TestNexusConfig6D:

    def test_services_nexus_toml_trellix_math_6(self):
        src = (SERVICES_CFG).read_text()
        assert re.search(r'trellix_math\s*=\s*6', src), \
            "services/config/nexus.toml trellix_math must be 6"

    def test_tests_nexus_toml_trellix_math_6(self):
        src = (TESTS_CFG).read_text()
        assert re.search(r'trellix_math\s*=\s*6', src), \
            "tests/config/nexus.toml trellix_math must be 6"

    def test_services_nexus_toml_entropy_score_in_vector_columns(self):
        assert "entropy_score" in (SERVICES_CFG).read_text()

    def test_services_nexus_toml_frequency_score_in_vector_columns(self):
        assert "frequency_score" in (SERVICES_CFG).read_text()

    def test_services_nexus_toml_analyzer_detection_method_in_context(self):
        assert "analyzer_detection_method" in (SERVICES_CFG).read_text()

    def test_services_nexus_toml_threat_source_url_in_context(self):
        assert "threat_source_url" in (SERVICES_CFG).read_text()

    def test_services_nexus_toml_threat_category_in_context(self):
        assert "threat_category" in (SERVICES_CFG).read_text()

    def test_services_nexus_toml_event_id_in_context(self):
        assert "event_id" in (SERVICES_CFG).read_text()

    def test_qdrant_init_trellix_math_size_6(self):
        src = QDRANT_SH.read_text()
        block = re.search(r'"trellix_math".*?"size":\s*(\d+)', src, re.DOTALL)
        assert block is not None, "trellix_math block not found in qdrant_init.sh"
        assert block.group(1) == "6", \
            f"qdrant_init.sh trellix_math size={block.group(1)}, expected 6"


# ══════════════════════════════════════════════════════════════════════════════
# Worker Qdrant Rust -- 6D vector processing
# ══════════════════════════════════════════════════════════════════════════════

class TestWorkerQdrantRust:

    def _src(self):
        return WORKER_RUST.read_text()

    def test_worker_rust_trellix_6d_branch_exists(self):
        src = self._src()
        assert '"trellix_math"' in src
        assert 'raw_math.len() == 6' in src

    def test_worker_rust_no_stale_4d_branch(self):
        assert '"trellix_math" && raw_math.len() == 4' not in self._src(), \
            "Stale 4D trellix_math branch still present in main.rs"

    def test_worker_rust_six_clamps_in_trellix_block(self):
        src = self._src()
        start = src.find('"trellix_math" && raw_math.len() == 6')
        assert start != -1
        # Find next else-if to bound the block, then count clamps within it
        next_branch = src.find("} else if", start + 10)
        block = src[start:next_branch] if next_branch != -1 else src[start:start + 900]
        assert block.count("clamp(0.0, 1.0)") >= 6

    def test_worker_rust_entropy_comment_present(self):
        assert "entropy" in self._src().lower()

    def test_worker_rust_frequency_comment_present(self):
        assert "frequency" in self._src().lower()

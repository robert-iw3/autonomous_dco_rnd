"""
test_sensor_sysmon.py -- Validation of the sysmon_sensor pipeline.

Coverage:
  Source files / Dockerfiles
  Parquet schema -- sysmon_event_id identifier, windows_math 6D vector
  Feature computation -- command_entropy, parent_child, integrity, grant_access, driver_trust
  Mock data -- all fields, all vector dimensions in [0, 1]
  Nexus config alignment -- windows_math=6, sysmon_event_id identifier
  Worker Qdrant Rust -- windows_math 6D branch
"""

import importlib.util
import io
import json
import math
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

REPO         = Path(__file__).parent.parent.parent       # project_empros/
ROOT         = REPO.parent
SYSMON_DIR   = ROOT / "windows" / "sysmon_sensor"
SERVICES_CFG = REPO / "services" / "config" / "nexus.toml"
TESTS_CFG    = REPO / "tests"    / "config" / "nexus.toml"
WORKER_RUST  = REPO / "services" / "worker_qdrant" / "src" / "main.rs"


def _load_schema():
    if str(SYSMON_DIR) not in sys.path:
        sys.path.insert(0, str(SYSMON_DIR))
    spec = importlib.util.spec_from_file_location("sysmon_schema", SYSMON_DIR / "schema.py")
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Source files ──────────────────────────────────────────────────────────────

class TestSysmonSourceFiles:

    def test_dockerfile_exists(self):
        assert (SYSMON_DIR / "Dockerfile").exists()

    def test_sysmon_sensor_script_exists(self):
        assert (SYSMON_DIR / "SysmonSensor.py").exists()

    def test_parquet_shipper_exists(self):
        assert (SYSMON_DIR / "parquet_shipper.py").exists()

    def test_schema_py_exists(self):
        assert (SYSMON_DIR / "schema.py").exists()

    def test_sysmon_config_xml_exists(self):
        assert (SYSMON_DIR / "sysmon_config.xml").exists()

    def test_requirements_txt_exists(self):
        assert (SYSMON_DIR / "requirements.txt").exists()

    def test_parquet_shipper_uses_hmac(self):
        src = (SYSMON_DIR / "parquet_shipper.py").read_text()
        assert "hmac" in src.lower() or "HMAC" in src


# ── Schema ────────────────────────────────────────────────────────────────────

class TestSysmonSchema:

    def _mod(self):
        return _load_schema()

    def test_schema_loads(self):
        assert self._mod() is not None

    def test_identifier_column_sysmon_event_id(self):
        names = [f.name for f in self._mod().SCHEMA]
        assert "sysmon_event_id" in names, "worker_qdrant duck-type identifier must be sysmon_event_id"

    def test_sensor_type_field_present(self):
        assert "sensor_type" in [f.name for f in self._mod().SCHEMA]

    def test_six_vector_scalar_fields_present(self):
        names = [f.name for f in self._mod().SCHEMA]
        for f in ("command_entropy", "parent_child_score", "integrity_score",
                  "anomaly_score", "grant_access_score", "driver_trust_score"):
            assert f in names, f"Missing vector column: {f}"

    def test_process_create_fields(self):
        names = [f.name for f in self._mod().SCHEMA]
        for f in ("Image", "CommandLine", "ParentImage", "User", "IntegrityLevel"):
            assert f in names

    def test_network_fields(self):
        names = [f.name for f in self._mod().SCHEMA]
        for f in ("DestinationIp", "DestinationPort", "Protocol"):
            assert f in names

    def test_driver_load_fields(self):
        names = [f.name for f in self._mod().SCHEMA]
        for f in ("ImageLoaded", "Signed", "SignatureStatus"):
            assert f in names

    def test_process_access_field(self):
        assert "GrantedAccess" in [f.name for f in self._mod().SCHEMA]


# ── Feature computation ───────────────────────────────────────────────────────

class TestSysmonFeatures:

    def _mod(self):
        return _load_schema()

    def test_command_entropy_empty(self):
        assert self._mod().compute_command_entropy("") == 0.0

    def test_command_entropy_base64_payload_higher(self):
        mod = self._mod()
        # Base64-encoded powershell payload should have higher entropy than simple command
        base64_cmd = "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0"
        simple_cmd = "ipconfig /all"
        assert mod.compute_command_entropy(base64_cmd) > mod.compute_command_entropy(simple_cmd)

    def test_command_entropy_bounded(self):
        mod = self._mod()
        for cmd in ["dir", "cmd.exe /c whoami", "A" * 100, "powershell -nop -enc " + "a" * 200]:
            e = mod.compute_command_entropy(cmd)
            assert 0.0 <= e <= 1.0

    def test_parent_child_winword_powershell(self):
        mod = self._mod()
        score = mod.compute_parent_child_score(
            r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        assert score >= 0.9

    def test_parent_child_explorer_chrome_normal(self):
        mod = self._mod()
        score = mod.compute_parent_child_score(
            r"C:\Windows\explorer.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )
        assert score == 0.0

    def test_integrity_score_system_is_max(self):
        assert self._mod().compute_integrity_score("System") == pytest.approx(1.0)

    def test_integrity_score_low_is_zero(self):
        assert self._mod().compute_integrity_score("Low") == pytest.approx(0.0)

    def test_grant_access_all_access_is_max(self):
        mod = self._mod()
        score = mod.compute_grant_access_score({"GrantedAccess": "0x1FFFFF"})
        assert score == pytest.approx(1.0)

    def test_grant_access_missing_is_zero(self):
        assert self._mod().compute_grant_access_score({}) == 0.0

    def test_driver_trust_unsigned_is_max(self):
        mod = self._mod()
        score = mod.compute_driver_trust_score({"Signed": False, "SignatureStatus": ""})
        assert score == pytest.approx(1.0)

    def test_driver_trust_valid_is_zero(self):
        mod = self._mod()
        score = mod.compute_driver_trust_score({"Signed": True, "SignatureStatus": "Valid"})
        assert score == pytest.approx(0.0)

    def test_compute_features_returns_six_floats(self):
        mod = self._mod()
        result = mod.compute_features({
            "CommandLine": "powershell.exe -nop -enc AAAA",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage": r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            "IntegrityLevel": "High",
            "GrantedAccess": None,
            "Signed": None,
            "SignatureStatus": None,
        })
        assert len(result) == 6
        for v in result:
            assert 0.0 <= v <= 1.0


# ── Mock data + Parquet roundtrip ─────────────────────────────────────────────

class TestSysmonMockData:

    def _build_row(self):
        return {
            "sensor_type":       "sysmon_sensor",
            "sensor_id":         "WORKSTATION-01",
            "timestamp":         1748000000.0,
            "sysmon_event_id":   1,
            "Image":             r"C:\Windows\System32\cmd.exe",
            "CommandLine":       "cmd.exe /c whoami",
            "ParentImage":       r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            "ParentCommandLine": None,
            "User":              "DOMAIN\\jdoe",
            "IntegrityLevel":    "High",
            "ProcessId":         1234,
            "ParentProcessId":   5678,
            "Hashes":            "SHA256=ABCD1234",
            "CurrentDirectory":  r"C:\Users\jdoe",
            "RuleName":          None,
            "DestinationIp":     None,
            "DestinationPort":   None,
            "Protocol":          None,
            "Initiated":         None,
            "ImageLoaded":       None,
            "Signed":            None,
            "SignatureStatus":   None,
            "SignatureIssuer":   None,
            "SourceImage":       None,
            "TargetImage":       None,
            "StartAddress":      None,
            "StartModule":       None,
            "GrantedAccess":     None,
            "TargetFilename":    None,
            "TargetObject":      None,
            "Details":           None,
            "EventType_reg":     None,
            "PipeName":          None,
            "QueryName":         None,
            "QueryResults":      None,
            "TamperingType":     None,
            "command_entropy":   0.55,
            "parent_child_score": 0.95,
            "integrity_score":   0.67,
            "anomaly_score":     0.5,
            "grant_access_score": 0.0,
            "driver_trust_score": 0.0,
            "payload_raw":       "{}",
        }

    def test_parquet_roundtrip(self):
        mod  = _load_schema()
        row  = self._build_row()
        arrays = [pa.array([row.get(f.name)], type=f.type) for f in mod.SCHEMA]
        table = pa.table({f.name: arrays[i] for i, f in enumerate(mod.SCHEMA)}, schema=mod.SCHEMA)
        buf = io.BytesIO()
        pq.write_table(table, buf, compression="zstd")
        buf.seek(0)
        t2 = pq.read_table(buf)
        assert t2.num_rows == 1
        assert t2.column("sysmon_event_id")[0].as_py() == 1

    def test_all_vector_scores_in_unit_interval(self):
        for field in ("command_entropy", "parent_child_score", "integrity_score",
                      "anomaly_score", "grant_access_score", "driver_trust_score"):
            v = self._build_row()[field]
            assert 0.0 <= v <= 1.0, f"{field}={v} out of [0,1]"


# ── Nexus config alignment ────────────────────────────────────────────────────

class TestSysmonNexusConfig:

    def test_services_cfg_windows_math_6(self):
        import re
        src = (SERVICES_CFG).read_text()
        assert re.search(r'windows_math\s*=\s*6', src)

    def test_services_cfg_sysmon_identifier_column(self):
        src = (SERVICES_CFG).read_text()
        sysmon_block = src[src.find("[schema_mappings.sysmon_sensor]"):]
        assert "sysmon_event_id" in sysmon_block

    def test_services_cfg_six_vector_columns(self):
        src = (SERVICES_CFG).read_text()
        for col in ("command_entropy", "parent_child_score", "integrity_score",
                    "anomaly_score", "grant_access_score", "driver_trust_score"):
            assert col in src, f"Missing sysmon vector column in nexus.toml: {col}"

    def test_worker_rust_windows_math_6d_branch(self):
        import re
        src = (WORKER_RUST).read_text()
        # worker_qdrant branches on active_source_type == "sysmon_sensor" (not "windows_math")
        assert re.search(r'"sysmon_sensor".*?raw_math\.len\(\)\s*==\s*6', src, re.DOTALL)

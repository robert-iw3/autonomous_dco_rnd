"""
Tier0 — schema and wire-contract tests (pure Python, no containers).

Validates that the Rust source files honour the expected column set,
required headers, sensor_id subsystem tags, MITRE mappings, beaconing
key format, and spool_replay flag.
"""
import re
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from vmware_connector_logic_mirror import (
    EXPECTED_PARQUET_COLUMNS,
    NULLABLE_COLUMNS,
    WIRE_SENSOR_TYPE,
    DEFAULT_SENSOR_ID,
    SPOOL_REPLAY,
    REQUIRED_HEADERS,
    EVENT_TYPES,
    SENSOR_ID_SUBSYSTEM_NSX,
    SENSOR_ID_SUBSYSTEM_VCENTER,
    SENSOR_ID_SUBSYSTEM_ESXI,
    TEMPORAL_CACHE_KEY_FORMAT,
    NSX_DENY_VERDICTS,
    NSX_ALLOW_VERDICTS,
    NSX_DENY_SCORE,
    NSX_ALLOW_SCORE,
    NSX_DENY_TACTIC,
    NSX_ALLOW_TACTIC,
    VCENTER_MITRE_MAPPINGS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path):
    with open(path) as f:
        return f.read()

@pytest.fixture(scope="module")
def transformer_src(src_dir):
    return _read(os.path.join(src_dir, "transformer.rs"))


@pytest.fixture(scope="module")
def transmitter_src(src_dir):
    return _read(os.path.join(src_dir, "transmitter.rs"))


@pytest.fixture(scope="module")
def config_src(src_dir):
    return _read(os.path.join(src_dir, "config.rs"))

# ---------------------------------------------------------------------------
# Parquet schema contract
# ---------------------------------------------------------------------------

class TestParquetSchema:
    def test_column_count(self, transmitter_src):
        """Rust schema must declare exactly 31 fields."""
        # Count Field::new( occurrences in the schema definition block.
        count = transmitter_src.count("Field::new(")
        assert count == len(EXPECTED_PARQUET_COLUMNS), (
            f"expected {len(EXPECTED_PARQUET_COLUMNS)} fields, found {count}"
        )

    def test_each_column_present(self, transmitter_src):
        """Every expected column name must appear in the Rust schema."""
        missing = [col for col in EXPECTED_PARQUET_COLUMNS if f'"{col}"' not in transmitter_src]
        assert not missing, f"Missing columns in Parquet schema: {missing}"

    def test_ml_result_is_nullable(self, transmitter_src):
        """ml_result must be the sole nullable column (true in last arg)."""
        for col in EXPECTED_PARQUET_COLUMNS:
            if col in NULLABLE_COLUMNS:
                assert re.search(rf'Field::new\(\s*"{col}"[^)]+,\s*true\s*\)', transmitter_src), \
                    f"{col} should be nullable=true"
            else:
                assert not re.search(rf'Field::new\(\s*"{col}"[^)]+,\s*true\s*\)', transmitter_src), \
                    f"{col} should not be nullable"

    def test_column_order(self, transmitter_src):
        """Column order in Rust source must match EXPECTED_PARQUET_COLUMNS."""
        positions = []
        for col in EXPECTED_PARQUET_COLUMNS:
            idx = transmitter_src.find(f'"{col}"')
            assert idx != -1, f"Column '{col}' not found in transmitter.rs"
            positions.append(idx)
        assert positions == sorted(positions), (
            "Columns are out of order vs EXPECTED_PARQUET_COLUMNS"
        )

# ---------------------------------------------------------------------------
# Wire contract / headers
# ---------------------------------------------------------------------------

class TestWireHeaders:
    def test_bearer_auth_present(self, transmitter_src):
        """transmitter.rs must call .bearer_auth for Authorization header."""
        assert "bearer_auth" in transmitter_src, \
            "Missing .bearer_auth() — gateway will reject every batch with 401"

    def test_all_required_headers_set(self, transmitter_src):
        """Each of the 7 required HTTP headers must be set in transmitter.rs."""
        for header in REQUIRED_HEADERS:
            if header == "Authorization":
                assert "bearer_auth" in transmitter_src, "Authorization/bearer_auth missing"
            else:
                assert f'"{header}"' in transmitter_src, \
                    f"Required header {header!r} not set in transmitter.rs"

    def test_content_type_is_parquet(self, transmitter_src):
        assert "application/vnd.apache.parquet" in transmitter_src

    def test_sensor_type_wire_value(self, transformer_src):
        """Connector must emit WIRE_SENSOR_TYPE constant on the wire."""
        assert f'"{WIRE_SENSOR_TYPE}"' in transformer_src, \
            f"WIRE_SENSOR_TYPE={WIRE_SENSOR_TYPE!r} not found in transformer.rs"

    def test_sensor_type_config_hardcoded(self, config_src):
        """sensor_type must be hardcoded to vmware_syslog, not env-configurable."""
        assert f'"{WIRE_SENSOR_TYPE}".to_string()' in config_src, \
            "sensor_type should be hardcoded in config.rs"
        assert "SENSOR_TYPE" not in config_src, \
            "sensor_type should not be driven by an env var"

# ---------------------------------------------------------------------------
# Sensor ID subsystem suffixes
# ---------------------------------------------------------------------------

class TestSensorIdSubsystems:
    def test_nsx_suffix(self, transformer_src):
        suffix = SENSOR_ID_SUBSYSTEM_NSX.lstrip("|")
        assert f"|{suffix}" in transformer_src, \
            f"NSX sensor_id subsystem suffix '|{suffix}' not in transformer.rs"

    def test_vcenter_suffix(self, transformer_src):
        suffix = SENSOR_ID_SUBSYSTEM_VCENTER.lstrip("|")
        assert f"|{suffix}" in transformer_src

    def test_esxi_suffix(self, transformer_src):
        suffix = SENSOR_ID_SUBSYSTEM_ESXI.lstrip("|")
        assert f"|{suffix}" in transformer_src

    def test_nsx_suffix_in_nsx_path(self, transformer_src):
        """The |nsx suffix must be in the nsx_flow transform function, not generic."""
        # Find the transform_nsx_flow function body.
        m = re.search(r"fn transform_nsx_flow[^{]+\{(.+?)\n    \}", transformer_src, re.DOTALL)
        assert m, "transform_nsx_flow not found"
        assert "|nsx" in m.group(1)

    def test_vcenter_suffix_in_cef_path(self, transformer_src):
        m = re.search(r"fn transform_cef[^{]+\{(.+?)\n    \}", transformer_src, re.DOTALL)
        assert m, "transform_cef not found"
        assert "|vcenter" in m.group(1)

    def test_esxi_suffix_in_generic_path(self, transformer_src):
        m = re.search(r"fn transform_generic[^{]+\{(.+?)\n    \}", transformer_src, re.DOTALL)
        assert m, "transform_generic not found"
        assert "|esxi" in m.group(1)

    def test_event_types_all_emitted(self, transformer_src):
        """All three event_type strings must appear in transformer.rs."""
        for et in EVENT_TYPES:
            assert f'"{et}"' in transformer_src, \
                f"event_type {et!r} not found in transformer.rs"

# ---------------------------------------------------------------------------
# NSX-T verdict mapping
# ---------------------------------------------------------------------------

class TestNSXVerdictMapping:
    def test_deny_verdicts_in_source(self, transformer_src):
        for v in NSX_DENY_VERDICTS:
            assert v in transformer_src, f"Deny verdict {v!r} not handled in transformer.rs"

    def test_allow_verdicts_in_source(self, transformer_src):
        for v in NSX_ALLOW_VERDICTS:
            assert v in transformer_src, f"Allow verdict {v!r} not handled in transformer.rs"

    def test_deny_score_value(self, transformer_src):
        assert f"({NSX_DENY_SCORE}," in transformer_src or f", {NSX_DENY_SCORE}," in transformer_src, \
            f"NSX_DENY_SCORE={NSX_DENY_SCORE} not found in transformer.rs"

    def test_deny_tactic_value(self, transformer_src):
        assert f'"{NSX_DENY_TACTIC}"' in transformer_src

    def test_allow_tactic_value(self, transformer_src):
        assert f'"{NSX_ALLOW_TACTIC}"' in transformer_src

    def test_deny_score_not_zero(self):
        assert NSX_DENY_SCORE > 0

    def test_allow_score_is_zero(self):
        assert NSX_ALLOW_SCORE == 0

# ---------------------------------------------------------------------------
# vCenter MITRE classification
# ---------------------------------------------------------------------------

class TestVCenterMITREMappings:
    @pytest.mark.parametrize("tactic,technique,score", [
        (v[1], v[2], v[0]) for v in VCENTER_MITRE_MAPPINGS.values() if v[2]
    ])
    def test_technique_in_source(self, transformer_src, tactic, technique, score):
        assert technique in transformer_src, \
            f"MITRE technique {technique!r} (tactic={tactic}) not in transformer.rs"

    def test_all_tactics_in_source(self, transformer_src):
        tactics = {v[1] for v in VCENTER_MITRE_MAPPINGS.values()}
        for tactic in tactics:
            assert tactic in transformer_src, \
                f"MITRE tactic {tactic!r} not found in transformer.rs"

    def test_credential_access_highest_score(self):
        assert VCENTER_MITRE_MAPPINGS["failed_login"][0] == 40

    def test_default_score_is_zero(self):
        assert VCENTER_MITRE_MAPPINGS["default"][0] == 0

# ---------------------------------------------------------------------------
# CEF priority — must check CEF before NSX flow
# ---------------------------------------------------------------------------

class TestCEFPriority:
    def test_cef_checked_before_nsx(self, transformer_src):
        """transform_line must check for CEF prefix before the NSX firewall path."""
        cef_pos = transformer_src.find('"CEF:"')
        nsx_pos = transformer_src.find("is_nsx_firewall")
        assert cef_pos != -1, "CEF check not found in transform_line"
        assert nsx_pos != -1, "is_nsx_firewall call not found"
        assert cef_pos < nsx_pos, \
            "CEF check must appear before is_nsx_firewall in transform_line"

# ---------------------------------------------------------------------------
# Beaconing / TemporalCache
# ---------------------------------------------------------------------------

class TestBeaconingCache:
    def test_cache_key_format(self, transformer_src):
        """TemporalCache must use src_ip|dst_ip as its key."""
        pattern = r'format!\(\s*"{}|{}"'
        # The Rust source encodes this as `format!("{}|{}", src_ip, dst_ip)`.
        assert '{}|{}' in transformer_src, \
            "TemporalCache key format {}|{} not found in transformer.rs"

    def test_temporal_cache_observe_called(self, transformer_src):
        assert "cache.observe(" in transformer_src or ".cache.observe(" in transformer_src

# ---------------------------------------------------------------------------
# spool_replay flag
# ---------------------------------------------------------------------------

class TestSpoolReplay:
    def test_spool_replay_hardcoded_true(self, config_src):
        """spool_replay must be hardcoded true — syslog connectors must replay on restart."""
        assert "spool_replay: true" in config_src, \
            "spool_replay must be hardcoded true in config.rs"

    def test_spool_replay_not_env_driven(self, config_src):
        assert "SPOOL_REPLAY" not in config_src, \
            "spool_replay should not be configurable via environment variable"

    def test_mirror_value_matches(self):
        assert SPOOL_REPLAY is True

# ---------------------------------------------------------------------------
# Auth token config
# ---------------------------------------------------------------------------

class TestAuthTokenConfig:
    def test_auth_token_field_exists(self, config_src):
        assert "auth_token" in config_src

    def test_auth_token_required_env(self, config_src):
        assert "AUTH_TOKEN" in config_src
        assert 'expect("AUTH_TOKEN must be set")' in config_src

    def test_default_sensor_id(self, config_src):
        assert DEFAULT_SENSOR_ID in config_src
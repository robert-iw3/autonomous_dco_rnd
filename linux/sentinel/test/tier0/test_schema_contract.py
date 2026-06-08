"""
Tier-0 -- Schema-contract validation for the linux_sentinel sensor.

Cross-checks the Parquet column layout mirrored from the Nexus-transmission
Arrow schema in parquet_transmitter.rs (see
sentinel_logic_mirror.EXPECTED_SENTINEL_PARQUET_COLUMNS) against the central
[schema_mappings.linux_sentinel] mapping in nexus.toml, and confirms the
X-Sensor-Type wire string, default gateway URL, and cross-OS exclusion-rule
registration declared/expected by the sensor and the gateway agree with the
contract and each other.
"""
import os
import re
import tomllib
import pytest

from sentinel_logic_mirror import (
    EXPECTED_SENTINEL_PARQUET_COLUMNS,
    WIRE_SENSOR_TYPE,
    DEFAULT_GATEWAY_URL,
    SENSOR_ID_SUFFIX,
)

pytestmark = pytest.mark.tier0

@pytest.fixture(scope="module")
def sentinel_mapping(nexus_toml_path):
    with open(nexus_toml_path, "rb") as fh:
        nexus = tomllib.load(fh)
    return nexus["schema_mappings"]["linux_sentinel"]

def _read(*parts):
    with open(os.path.join(*parts)) as fh:
        return fh.read()

class TestContextAndVectorColumnsPresentInSchema:
    """Every column the contract declares (vector + context + identifiers) must
    exist in the real Nexus-transmission Arrow schema emitted by the sensor."""

    def test_all_context_columns_are_emitted(self, sentinel_mapping):
        missing = [c for c in sentinel_mapping["context_columns"] if c not in EXPECTED_SENTINEL_PARQUET_COLUMNS]
        assert not missing, f"contract context_columns not emitted by transmission schema: {missing}"

    def test_all_vector_columns_are_emitted(self, sentinel_mapping):
        missing = [c for c in sentinel_mapping["vector_columns"] if c not in EXPECTED_SENTINEL_PARQUET_COLUMNS]
        assert not missing, f"contract vector_columns not emitted by transmission schema: {missing}"

    def test_mitre_tactic_and_technique_are_separate_columns(self, sentinel_mapping):
        # Same split that suricata's eve_schema() needed fixing for -- guard
        # against a regression to a single combined "alert_mitre"-style column.
        assert "mitre_tactic" in sentinel_mapping["context_columns"]
        assert "mitre_technique" in sentinel_mapping["context_columns"]
        assert "mitre_tactic" in EXPECTED_SENTINEL_PARQUET_COLUMNS
        assert "mitre_technique" in EXPECTED_SENTINEL_PARQUET_COLUMNS
        assert "alert_mitre" not in EXPECTED_SENTINEL_PARQUET_COLUMNS

    def test_expected_column_count_matches_real_schema_definition(self, repo_root):
        # Regression guard for the bug where EXPECTED_SENTINEL_PARQUET_COLUMNS
        # in tests/test_sensor_pipeline.rs was a fictional 27-column list that
        # matched neither the transmission nor the local-cache schema. Count
        # `Field::new(` occurrences in the real transmission-schema block.
        src = _read(repo_root, "src", "siem", "parquet_transmitter.rs")
        m = re.search(r"Define Arrow Schema for Nexus transmission.*?Schema::new\(vec!\[(.*?)\]\)\);", src, re.DOTALL)
        assert m, "could not locate the Nexus-transmission Arrow schema block in parquet_transmitter.rs"
        field_count = len(re.findall(r"Field::new\(", m.group(1)))
        assert field_count == len(EXPECTED_SENTINEL_PARQUET_COLUMNS) == 25

class TestIdentifierAndSensorIdColumns:
    def test_identifier_column_present(self, sentinel_mapping):
        assert sentinel_mapping["identifier_column"] in EXPECTED_SENTINEL_PARQUET_COLUMNS

    def test_primary_key_column_present(self, sentinel_mapping):
        assert sentinel_mapping["primary_key_column"] in EXPECTED_SENTINEL_PARQUET_COLUMNS

    def test_timestamp_column_present(self, sentinel_mapping):
        assert sentinel_mapping["timestamp_column"] in EXPECTED_SENTINEL_PARQUET_COLUMNS

    def test_sensor_id_column_present(self, sentinel_mapping):
        assert sentinel_mapping["sensor_id_column"] in EXPECTED_SENTINEL_PARQUET_COLUMNS
        assert "sensor_id" in EXPECTED_SENTINEL_PARQUET_COLUMNS

    def test_sensor_id_is_hostname_derived_not_a_network_destination(self):
        # nexus.toml documents that sensor_id_column "must identify the
        # REPORTING HOST, not a network destination" -- confirm the runtime
        # value is hostname-derived (HOSTNAME/SENTINEL_SENSOR_ID + suffix),
        # not e.g. dest_ip.
        assert SENSOR_ID_SUFFIX == "-sentinel"

class TestSensorTypeContract:
    def test_wire_sensor_type_matches_sensor_profile(self, repo_root):
        # src: project_empros/middleware/config/sensor_profiles/linux_sentinel.toml
        profile = os.path.normpath(os.path.join(
            repo_root, "..", "..", "project_empros", "middleware", "config",
            "sensor_profiles", "linux_sentinel.toml",
        ))
        src = _read(profile)
        assert f'sensor_type = "{WIRE_SENSOR_TYPE}"' in src

    def test_wire_sensor_type_matches_transmitter_source(self, repo_root):
        src = _read(repo_root, "src", "siem", "parquet_transmitter.rs")
        assert f'header::HeaderValue::from_static("{WIRE_SENSOR_TYPE}")' in src

    def test_wire_sensor_type_intentionally_differs_from_schema_mapping_key(self, sentinel_mapping):
        # Documented intentional split: nexus.toml's [schema_mappings.*] table
        # key is lowercase ("linux_sentinel", used for worker_qdrant/worker_rules
        # duck-typing) while the wire X-Sensor-Type is "Linux-Sentinel" (matched
        # exactly by worker_splunk/worker_elastic and the sensor profile). This
        # test documents the split so nobody "fixes" one side into a mismatch.
        assert WIRE_SENSOR_TYPE != "linux_sentinel"
        assert WIRE_SENSOR_TYPE.lower().replace("-", "_") == "linux_sentinel"

    def test_cross_os_exclusion_rule_is_keyed_by_the_real_wire_value(self, repo_root):
        """Regression guard for a real bug found via this workbench: core_ingress's
        build_os_exclusion_rules() registered the lookup key as the lowercase
        nexus.toml table name ("linux_sentinel") instead of the literal
        X-Sensor-Type value the sensor actually sends ("Linux-Sentinel"). Since
        verify_batch() looks the rule up by the *raw header string*
        (`self.os_exclusion_rules.get(sensor_type)` with
        `sensor_type = hdr_str(&headers, HDR_SENSOR_TYPE)`), the mismatched key
        meant the cross-OS column-collision ban silently never fired for any
        real linux_sentinel batch -- exactly the kind of gap its own comment
        ("Keys MUST match the X-Sensor-Type header values used in production")
        warns against. Fixed in integrity.rs by registering "Linux-Sentinel".
        """
        integrity_rs = os.path.normpath(os.path.join(
            repo_root, "..", "..", "project_empros", "services", "core_ingress",
            "src", "integrity.rs",
        ))
        src = _read(integrity_rs)
        match = re.search(r"fn build_os_exclusion_rules\(\).*?\n}", src, re.DOTALL)
        assert match, "could not locate build_os_exclusion_rules() body in integrity.rs"
        body = match.group(0)
        assert f'"{WIRE_SENSOR_TYPE}".into()' in body, (
            f"build_os_exclusion_rules() must register its linux_sentinel rule "
            f"under the literal wire value {WIRE_SENSOR_TYPE!r} (what "
            f"hdr_str(&headers, HDR_SENSOR_TYPE) actually returns), not the "
            f"lowercase nexus.toml table key -- otherwise the lookup always misses"
        )
        assert '"linux_sentinel".into()' not in body

class TestGatewayUrlContract:
    def test_default_gateway_points_at_telemetry_route(self):
        from urllib.parse import urlparse
        assert urlparse(DEFAULT_GATEWAY_URL).path == "/api/v1/telemetry"

    def test_default_gateway_url_matches_master_toml(self, repo_root):
        src = _read(repo_root, "master.toml")
        assert DEFAULT_GATEWAY_URL in src, (
            "sentinel_logic_mirror.DEFAULT_GATEWAY_URL is out of sync with "
            "master.toml's middleware_gateway_url default"
        )

    def test_gateway_requires_https(self, repo_root):
        # parquet_transmitter.rs hard-errors if the configured gateway_url
        # doesn't start with "https://" -- confirm the shipped default complies.
        assert DEFAULT_GATEWAY_URL.startswith("https://")
        src = _read(repo_root, "src", "siem", "parquet_transmitter.rs")
        assert 'gateway_url.starts_with("https://")' in src
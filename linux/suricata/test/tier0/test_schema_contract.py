"""
Tier-0 -- Schema-contract validation for the suricata_eve sensor.

Cross-checks the Parquet column layout mirrored from `eve_schema()` in
main.rs (see eve_logic_mirror.EVE_SCHEMA_COLUMNS) against the central
[schema_mappings.suricata_eve] mapping in nexus.toml, and confirms the
sensor_type/routing string and gateway URL declared in the transmitter
match the contract and the deployment defaults.
"""
import re
import tomllib
import pytest

from eve_logic_mirror import (
    EVE_SCHEMA_COLUMNS,
    SENSOR_TYPE,
    DEFAULT_GATEWAY_URL,
)

pytestmark = pytest.mark.tier0

@pytest.fixture(scope="module")
def suricata_mapping(nexus_toml_path):
    with open(nexus_toml_path, "rb") as fh:
        nexus = tomllib.load(fh)
    return nexus["schema_mappings"]["suricata_eve"]

class TestContextColumnsPresentInSchema:
    """Every context_column the contract declares must exist as an emitted Parquet column.

    This is a regression guard for the bug fixed in main.rs where the contract
    declared `mitre_tactic`/`mitre_technique` but the transmitter only emitted a
    single combined `alert_mitre` column -- a name neither side agreed on.
    """

    def test_all_context_columns_are_emitted(self, suricata_mapping):
        missing = [c for c in suricata_mapping["context_columns"] if c not in EVE_SCHEMA_COLUMNS]
        assert not missing, f"contract context_columns not emitted by eve_schema(): {missing}"

    def test_no_orphaned_alert_mitre_column(self):
        # Regression guard: the old single-field name must not resurface.
        assert "alert_mitre" not in EVE_SCHEMA_COLUMNS

    def test_mitre_tactic_and_technique_are_separate_columns(self, suricata_mapping):
        assert "mitre_tactic" in suricata_mapping["context_columns"]
        assert "mitre_technique" in suricata_mapping["context_columns"]
        assert "mitre_tactic" in EVE_SCHEMA_COLUMNS
        assert "mitre_technique" in EVE_SCHEMA_COLUMNS

class TestIdentifierAndSensorIdColumns:
    def test_identifier_column_present(self, suricata_mapping):
        assert suricata_mapping["identifier_column"] in EVE_SCHEMA_COLUMNS

    def test_primary_key_column_present(self, suricata_mapping):
        assert suricata_mapping["primary_key_column"] in EVE_SCHEMA_COLUMNS

    def test_timestamp_column_present(self, suricata_mapping):
        assert suricata_mapping["timestamp_column"] in EVE_SCHEMA_COLUMNS

    def test_sensor_id_column_present(self, suricata_mapping):
        assert suricata_mapping["sensor_id_column"] in EVE_SCHEMA_COLUMNS
        assert "sensor_id" in EVE_SCHEMA_COLUMNS

class TestSensorTypeContract:
    def test_sensor_type_matches_schema_mapping_key(self):
        # The [schema_mappings.suricata_eve] table key IS the routed sensor_type.
        assert SENSOR_TYPE == "suricata_eve"

    def test_sensor_type_not_a_cross_os_collision_key(self, repo_root):
        """Confirm 'suricata_eve' is not registered in core_ingress's
        build_exclusion_rules() collision map (which would imply this sensor_type
        carries OS-specific columns subject to cross-platform leakage checks)."""
        import os
        integrity_rs = os.path.join(
            repo_root, "..", "..", "project_empros", "middleware", "src",
            "core_ingress", "src", "integrity.rs",
        )
        integrity_rs = os.path.normpath(integrity_rs)
        with open(integrity_rs) as fh:
            src = fh.read()
        match = re.search(r"fn build_exclusion_rules\(\).*?\n}\n", src, re.DOTALL)
        assert match, "could not locate build_exclusion_rules() body in integrity.rs"
        body = match.group(0)
        # The function registers connector keys (e.g. "aws-vpc-flow-connector",
        # "network_tap") that opt into CrossOsCollision column-exclusion checks.
        # Neither "suricata_eve" nor any suricata-* connector key should appear
        # as a registered key -- this sensor_type carries its own dedicated
        # vector space (c2_math) and isn't subject to that collision map.
        assert SENSOR_TYPE not in body
        assert "suricata" not in body.lower()

class TestGatewayUrlContract:
    def test_default_gateway_points_at_telemetry_route(self):
        from urllib.parse import urlparse
        assert urlparse(DEFAULT_GATEWAY_URL).path == "/api/v1/telemetry"

    def test_default_gateway_url_matches_source(self, repo_root):
        import os
        main_rs = os.path.join(repo_root, "transmitter", "src", "main.rs")
        with open(main_rs) as fh:
            src = fh.read()
        assert DEFAULT_GATEWAY_URL in src, (
            "eve_logic_mirror.DEFAULT_GATEWAY_URL is out of sync with "
            "Config::from_env()'s NEXUS_GATEWAY_URL fallback in main.rs"
        )

    def test_launch_script_default_matches(self, repo_root):
        import os
        launch_sh = os.path.join(repo_root, "launch.sh")
        with open(launch_sh) as fh:
            src = fh.read()
        assert DEFAULT_GATEWAY_URL in src
"""
Tier-0 -- Schema-contract validation for the network_tap (arkime-ml-gateway) sensor.
"""
import os
import re
import tomllib
import pytest

from network_tap_logic_mirror import (
    EXPECTED_NETWORK_TAP_PARQUET_COLUMNS,
    SCHEMA_VERSION,
    WIRE_SENSOR_TYPE,
    DEFAULT_GATEWAY_URL,
    CONTENT_TYPE,
    sensor_id_for,
)

pytestmark = pytest.mark.tier0

@pytest.fixture(scope="module")
def network_tap_mapping(nexus_toml_path):
    with open(nexus_toml_path, "rb") as fh:
        nexus = tomllib.load(fh)
    return nexus["schema_mappings"]["network_tap"]

@pytest.fixture(scope="module")
def gateway_config(gateway_dir):
    with open(os.path.join(gateway_dir, "config.toml"), "rb") as fh:
        return tomllib.load(fh)

def _read(*parts):
    with open(os.path.join(*parts)) as fh:
        return fh.read()

# -----------------------------------------------------------------------------
# Contract columns must actually be emitted by the real transmission schema
# -----------------------------------------------------------------------------

class TestContractColumnsPresentInSchema:
    def test_all_vector_columns_are_emitted(self, network_tap_mapping):
        missing = [c for c in network_tap_mapping["vector_columns"]
                   if c not in EXPECTED_NETWORK_TAP_PARQUET_COLUMNS]
        assert not missing, f"contract vector_columns not emitted by transmission schema: {missing}"

    def test_all_context_columns_are_emitted(self, network_tap_mapping):
        missing = [c for c in network_tap_mapping["context_columns"]
                   if c not in EXPECTED_NETWORK_TAP_PARQUET_COLUMNS]
        assert not missing, f"contract context_columns not emitted by transmission schema: {missing}"

    def test_identifier_primary_key_timestamp_sensor_id_columns_present(self, network_tap_mapping):
        for key in ("identifier_column", "primary_key_column", "timestamp_column", "sensor_id_column"):
            col = network_tap_mapping[key]
            assert col in EXPECTED_NETWORK_TAP_PARQUET_COLUMNS, \
                f"{key} = {col!r} is not an emitted Parquet column"

    def test_sensor_id_column_maps_to_sensor_name_not_a_destination(self, network_tap_mapping):
        # The contract documents sensor_id_column must identify the REPORTING
        # HOST. network_tap intentionally maps it to "sensor_name" (the
        # human-readable deploy-time identity), not e.g. dst_ip/hostname --
        # confirm that mapping holds and "sensor_name" is itself emitted.
        assert network_tap_mapping["sensor_id_column"] == "sensor_name"
        assert "sensor_name" in EXPECTED_NETWORK_TAP_PARQUET_COLUMNS

    def test_expected_column_count_matches_real_schema_definition(self, gateway_dir):
        # Regression guard: count Field::new( occurrences in the real
        # flow_schema() block so a future column add/remove that isn't
        # mirrored here fails loudly rather than silently drifting.
        src = _read(gateway_dir, "src", "transmit", "nexus.rs")
        m = re.search(r"fn flow_schema\(\).*?Schema::new\(vec!\[(.*?)\]\)\)", src, re.DOTALL)
        assert m, "could not locate flow_schema()'s Schema::new(vec![...]) block in transmit/nexus.rs"
        field_names = re.findall(r'Field::new\(\s*"([a-z0-9_]+)"', m.group(1))
        assert field_names == EXPECTED_NETWORK_TAP_PARQUET_COLUMNS
        assert len(field_names) == 48

    def test_schema_version_constant_is_emitted_verbatim(self, gateway_dir):
        src = _read(gateway_dir, "src", "transmit", "nexus.rs")
        assert f'const SCHEMA_VERSION: &str = "{SCHEMA_VERSION}"' in src
        assert "schema_version" in EXPECTED_NETWORK_TAP_PARQUET_COLUMNS


# -----------------------------------------------------------------------------
# Sensor-type / sensor-id wire contract
# -----------------------------------------------------------------------------

class TestSensorTypeAndIdContract:
    def test_config_toml_sensor_type_matches_mirror(self, gateway_config):
        assert gateway_config["global"]["sensor_type"] == WIRE_SENSOR_TYPE

    def test_sensor_profile_sensor_type_matches_config_toml(self, repo_root, gateway_config):
        profile = os.path.join(repo_root, "project_empros", "middleware", "config",
                               "sensor_profiles", "network_tap.toml")
        src = _read(profile)
        assert f'sensor_type = "{gateway_config["global"]["sensor_type"]}"' in src

    def test_wire_sensor_type_matches_schema_mapping_table_key(self, network_tap_mapping):
        # Unlike linux_sentinel (deliberately split: "Linux-Sentinel" wire vs
        # "linux_sentinel" table key), network_tap's wire X-Sensor-Type is
        # config-driven and happens to equal the lowercase nexus.toml table
        # key verbatim -- document that equivalence so nobody "splits" it by
        # analogy to sentinel without the matching core_ingress registration.
        assert WIRE_SENSOR_TYPE == "network_tap"

    def test_sensor_id_is_derived_from_name_and_type_not_a_network_address(self, gateway_dir, gateway_config):
        # src: transmit/nexus.rs:174
        #   let sensor_id = format!("{}-{}", cfg.global.sensor_name, cfg.global.sensor_type);
        src = _read(gateway_dir, "src", "transmit", "nexus.rs")
        assert 'format!("{}-{}", cfg.global.sensor_name, cfg.global.sensor_type)' in src
        expected = sensor_id_for(gateway_config["global"]["sensor_name"], gateway_config["global"]["sensor_type"])
        assert expected == "network-tap-alpha-network_tap"


# -----------------------------------------------------------------------------
# Gateway URL contract
# -----------------------------------------------------------------------------

class TestGatewayUrlContract:
    def test_default_gateway_points_at_telemetry_route(self):
        from urllib.parse import urlparse
        assert urlparse(DEFAULT_GATEWAY_URL).path == "/api/v1/telemetry"

    def test_default_gateway_url_matches_shipped_config_toml(self, gateway_config):
        assert gateway_config["nexus"]["gateway_url"] == DEFAULT_GATEWAY_URL

    def test_gateway_requires_https(self, gateway_dir):
        # config::load() hard-errors if gateway_url doesn't start with "https://"
        assert DEFAULT_GATEWAY_URL.startswith("https://")
        src = _read(gateway_dir, "src", "config.rs")
        assert 'cfg.nexus.gateway_url.starts_with("https://")' in src

    def test_middleware_profile_endpoint_uses_registered_ingress_route(self, repo_root):
        from urllib.parse import urlparse
        profile = os.path.join(repo_root, "project_empros", "middleware", "config",
                               "sensor_profiles", "network_tap.toml")
        src = _read(profile)
        m = re.search(r'middleware_url\s*=\s*"([^"]+)"', src)
        assert m
        assert urlparse(m.group(1)).path == "/api/v1/telemetry"


# -----------------------------------------------------------------------------
# Content-Type contract
# -----------------------------------------------------------------------------

class TestContentTypeContract:
    def test_content_type_is_parquet(self, gateway_dir):
        assert CONTENT_TYPE == "application/vnd.apache.parquet"
        src = _read(gateway_dir, "src", "transmit", "nexus.rs")
        assert f'header::HeaderValue::from_static("{CONTENT_TYPE}")' in src
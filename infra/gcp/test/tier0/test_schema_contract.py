"""
Tier-0 -- Schema-contract validation for the Nexus GCP connectors
(nexus-gcp-audit-connector, nexus-gcp-scc-connector, nexus-gcp-vpc-connector).
"""
import os
import re
import pytest

from gcp_connectors_logic_mirror import (
    EXPECTED_GCP_PARQUET_COLUMNS,
    NULLABLE_COLUMNS,
    WIRE_SENSOR_TYPE,
    DEFAULT_SENSOR_ID,
    WIRE_EVENT_TYPE,
    CONTENT_TYPE,
    SPOOL_REPLAY,
    sensor_id_for_vpc,
)

pytestmark = pytest.mark.tier0

CONNECTOR_CRATE_NAME = {
    "audit": "nexus-gcp-audit-connector",
    "scc":   "nexus-gcp-scc-connector",
    "vpc":   "nexus-gcp-vpc-connector",
}

def _name(connector_dir):
    return os.path.basename(connector_dir)

def _read(*parts):
    with open(os.path.join(*parts)) as fh:
        return fh.read()

# ---------------------------------------------------------------------------
# transmitter.rs identity check -- byte-identical across all three crates.
# ---------------------------------------------------------------------------

class TestTransmitterIsSharedVerbatim:
    def test_transmitter_byte_identical_across_all_three_crates(self, gcp_dir):
        """HMAC formula, Parquet schema, and headers are shared verbatim.
        Any drift would silently produce a wire contract mismatch that
        core_ingress would reject for the diverged connector."""
        audit_src = _read(gcp_dir, "audit", "src", "transmitter.rs")
        for other in ("scc", "vpc"):
            assert _read(gcp_dir, other, "src", "transmitter.rs") == audit_src, \
                f"{other}/src/transmitter.rs has drifted from audit's -- HMAC formula, " \
                f"schema, or headers may now differ across connectors"

    def test_config_carries_auth_token_required_by_shared_transmitter(self, connector_dir):
        """REAL BUG regression guard: original GCP configs lacked auth_token /
        AUTH_TOKEN -- the shared transmitter.rs calls .bearer_auth(&self.config.auth_token)
        to send the Authorization header that core_ingress::validate_token requires.
        Without this field cargo check fails with E0609 for all three crates."""
        name = _name(connector_dir)
        config_src = _read(connector_dir, "src", "config.rs")
        assert "pub auth_token: String" in config_src, \
            f"{name}: config.rs Config struct is missing `pub auth_token: String` -- " \
            f"transmitter.rs reads self.config.auth_token for bearer_auth"
        assert 'env::var("AUTH_TOKEN")' in config_src, \
            f"{name}: config.rs does not read AUTH_TOKEN from the environment"

    def test_spool_replay_disabled_for_queue_backed_transport(self, connector_dir):
        """Pub/Sub redelivers nacked messages -- replaying the spool on boot would
        duplicate data. spool_replay must be hardcoded false, never env-configurable."""
        name = _name(connector_dir)
        config_src = _read(connector_dir, "src", "config.rs")
        assert "spool_replay: false" in config_src, \
            f"{name}: config.rs does not hardcode spool_replay: false -- " \
            f"Pub/Sub is queue-backed; spool replay would duplicate data on restart"
        assert SPOOL_REPLAY is False

    def test_config_carries_spool_bound_fields_required_by_shared_transmitter(self, connector_dir):
        """Spool bound fields (max_spool_bytes, max_spool_files) must be present in
        all three configs -- the shared transmitter.rs reads them unconditionally."""
        name = _name(connector_dir)
        config_src = _read(connector_dir, "src", "config.rs")
        for field, ftype in (("max_spool_bytes", "u64"), ("max_spool_files", "usize")):
            assert f"pub {field}: {ftype}" in config_src, \
                f"{name}: config.rs missing `pub {field}: {ftype}` -- transmitter.rs reads it"

    def test_crate_name_in_cargo_toml_matches_expected(self, connector_dir):
        name = _name(connector_dir)
        cargo = _read(connector_dir, "Cargo.toml")
        assert f'name = "{CONNECTOR_CRATE_NAME[name]}"' in cargo

# ---------------------------------------------------------------------------
# Parquet schema contract
# ---------------------------------------------------------------------------

class TestContractColumnsPresentInSchema:
    def test_all_vector_columns_are_emitted(self, nexus_toml_path):
        import tomllib
        with open(nexus_toml_path, "rb") as fh:
            nexus = tomllib.load(fh)
        mapping = nexus["schema_mappings"]["cloud_flow"]
        missing = [c for c in mapping["vector_columns"] if c not in EXPECTED_GCP_PARQUET_COLUMNS]
        assert not missing, f"contract vector_columns not emitted by GCP schema: {missing}"

    def test_all_context_columns_are_emitted(self, nexus_toml_path):
        import tomllib
        with open(nexus_toml_path, "rb") as fh:
            nexus = tomllib.load(fh)
        mapping = nexus["schema_mappings"]["cloud_flow"]
        missing = [c for c in mapping["context_columns"] if c not in EXPECTED_GCP_PARQUET_COLUMNS]
        assert not missing, f"contract context_columns not emitted by GCP schema: {missing}"

    def test_expected_column_count_and_order_matches_real_schema_definition(self, connector_dir):
        """Regression guard: extracts Field::new() names/order/nullability directly
        from to_parquet() Schema block -- a reorder without mirroring it here fails."""
        src = _read(connector_dir, "src", "transmitter.rs")
        m = re.search(r"fn to_parquet\(.*?Schema::new\(vec!\[(.*?)\]\)\);", src, re.DOTALL)
        assert m, "could not locate to_parquet()'s Schema::new(vec![...]) in transmitter.rs"
        fields = re.findall(r'Field::new\(\s*"([a-z0-9_]+)",\s*DataType::\w+,\s*(true|false)\)', m.group(1))
        names = [n for n, _ in fields]
        nullable = tuple(n for n, is_null in fields if is_null == "true")
        assert names == EXPECTED_GCP_PARQUET_COLUMNS
        assert len(names) == 31
        assert nullable == NULLABLE_COLUMNS

    def test_unified_flow_record_struct_field_order_matches_parquet_schema(self, connector_dir):
        """Arrow builds each column array from records.iter().map(|r| r.<field>).
        A struct/schema field-order mismatch silently transposes column data on the wire."""
        src = _read(connector_dir, "src", "transformer.rs")
        m = re.search(r"pub struct UnifiedFlowRecord \{(.*?)\n\}", src, re.DOTALL)
        assert m, "could not locate UnifiedFlowRecord struct in transformer.rs"
        names = re.findall(r"pub (\w+):", m.group(1))
        assert names == EXPECTED_GCP_PARQUET_COLUMNS

# ---------------------------------------------------------------------------
# Sensor-type / sensor-id / event-type wire contract
# ---------------------------------------------------------------------------

class TestSensorTypeAndIdContract:
    def test_hardcoded_sensor_type_matches_mirror(self, connector_dir):
        name = _name(connector_dir)
        src = _read(connector_dir, "src", "config.rs")
        assert f'sensor_type: "{WIRE_SENSOR_TYPE[name]}".to_string()' in src

    def test_default_sensor_id_matches_mirror(self, connector_dir):
        name = _name(connector_dir)
        src = _read(connector_dir, "src", "config.rs")
        assert f'unwrap_or_else(|_| "{DEFAULT_SENSOR_ID[name]}".to_string())' in src

    def test_wire_sensor_type_values_are_distinct_per_connector(self):
        values = list(WIRE_SENSOR_TYPE.values())
        assert len(values) == len(set(values)), "connectors must not share a wire X-Sensor-Type"

    def test_event_type_literal_stamped_in_transformer(self, connector_dir):
        """Each connector stamps a hardcoded event_type string that core_ingress uses
        to route/identify records within the cloud_flow vector."""
        name = _name(connector_dir)
        src = _read(connector_dir, "src", "transformer.rs")
        expected = WIRE_EVENT_TYPE[name]
        assert f'event_type: "{expected}".to_string()' in src, \
            f"{name}: transformer.rs does not stamp event_type: \"{expected}\".to_string()"

    def test_vpc_sensor_id_formula_encodes_project_region_subnetwork(self, connector_dir):
        """vpc encodes 4-component identity (project|env|region|subnetwork) -- richer
        than AWS/Azure 3-tuples because VPC flow logs carry subnetwork context inline.
        audit/scc use a flat SENSOR_ID env var (no runtime derivation)."""
        name = _name(connector_dir)
        src = _read(connector_dir, "src", "transformer.rs")
        if name == "vpc":
            assert 'format!("{}|{}|{}|{}", project_id, environment, region, subnetwork)' in src
            assert sensor_id_for_vpc("proj", "prod", "us-central1", "default") == \
                "proj|prod|us-central1|default"
        else:
            assert 'format!("{}|{}|{}|{}", project_id, environment, region, subnetwork)' not in src, \
                f"{name}: unexpectedly has vpc-style 4-component sensor_id derivation"

    def test_cloud_connector_profile_documents_gcp_sensor_types(self, repo_root):
        """gcp_connector.toml must document all three GCP sensor_type strings so
        middleware config stays in sync with actual wire values."""
        import os
        profile = os.path.join(repo_root, "project_empros", "middleware", "config",
                               "sensor_profiles", "gcp_connector.toml")
        src = _read(profile)
        for sensor_type in WIRE_SENSOR_TYPE.values():
            assert sensor_type in src, \
                f"gcp_connector.toml no longer documents sensor_type {sensor_type!r}"

# ---------------------------------------------------------------------------
# Content-Type / Authorization header contract
# ---------------------------------------------------------------------------

class TestContentTypeAndAuthContract:
    def test_content_type_is_parquet(self, connector_dir):
        src = _read(connector_dir, "src", "transmitter.rs")
        assert f'.header("Content-Type", "{CONTENT_TYPE}")' in src

    def test_bearer_auth_sent_for_authorization_header(self, connector_dir):
        """REAL BUG regression guard: original GCP transmitters lacked bearer_auth --
        core_ingress::validate_token rejects every batch with 401 UNAUTHORIZED
        before integrity-header logic runs. Confirm bearer_auth is present."""
        name = _name(connector_dir)
        src = _read(connector_dir, "src", "transmitter.rs")
        assert ".bearer_auth(&self.config.auth_token)" in src, \
            f"{name}: transmitter.rs does not call bearer_auth -- " \
            f"every batch is rejected with 401 by core_ingress::validate_token"

    def test_six_literal_headers_plus_bearer_auth_equals_seven_required(self, connector_dir):
        src = _read(connector_dir, "src", "transmitter.rs")
        literal_headers = re.findall(r'\.header\("([A-Za-z-]+)",', src)
        assert set(literal_headers) | {"Authorization"} == set(REQUIRED_HEADERS)
        assert len(literal_headers) == 6

# ---------------------------------------------------------------------------
# SCC-specific runtime contract (dedup and poison-loop guard)
# ---------------------------------------------------------------------------

class TestSCCSpecificContract:
    def test_scc_has_dedup_logic_to_suppress_renotified_findings(self, connector_dir):
        """SCC re-notifies on finding state changes -- without dedup the connector
        would forward the same finding multiple times to the gateway."""
        name = _name(connector_dir)
        if name != "scc":
            pytest.skip(f"{name}: dedup contract only applies to scc")
        main_src = _read(connector_dir, "src", "main.rs")
        assert "scc_dedup_key" in main_src, \
            f"scc/main.rs no longer has scc_dedup_key -- finding dedup removed"
        assert "cache.contains" in main_src, \
            f"scc/main.rs no longer checks the dedup cache before processing"

    def test_scc_acks_undecodable_payloads_to_avoid_poison_loop(self, connector_dir):
        """Undecodable payloads must be acked immediately so they don't loop forever
        in the subscription and block real findings."""
        name = _name(connector_dir)
        if name != "scc":
            pytest.skip(f"{name}: poison-loop guard only in scc")
        main_src = _read(connector_dir, "src", "main.rs")
        assert "Undecodable SCC payload" in main_src, \
            f"scc/main.rs no longer logs and acks undecodable payloads"

    def test_scc_severity_score_mapping_matches_mirror(self, connector_dir):
        """Score derivation: CRITICAL=95, HIGH=75, MEDIUM=50, LOW=25.
        A change here would re-bucket findings in the risk engine."""
        name = _name(connector_dir)
        if name != "scc":
            pytest.skip(f"{name}: severity-score mapping only in scc")
        src = _read(connector_dir, "src", "transformer.rs")
        assert '"CRITICAL" => 95' in src
        assert '"HIGH" => 75' in src
        assert '"MEDIUM" => 50' in src
        assert '"LOW" => 25' in src
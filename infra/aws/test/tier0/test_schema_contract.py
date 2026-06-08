"""
Tier-0 -- Schema-contract validation for the Nexus AWS connectors
(nexus-aws-vpc-connector, nexus-aws-cloudtrail-connector, nexus-aws-guardduty-connector).
"""
import os
import re
import tomllib
import pytest

from aws_connectors_logic_mirror import (
    EXPECTED_AWS_PARQUET_COLUMNS,
    NULLABLE_COLUMNS,
    WIRE_SENSOR_TYPE,
    DEFAULT_SENSOR_ID,
    CONTENT_TYPE,
    sensor_id_for,
)

pytestmark = pytest.mark.tier0

CONNECTOR_CRATE_NAME = {
    "vpc": "nexus-aws-vpc-connector",
    "cloudtrail": "nexus-aws-cloudtrail-connector",
    "guardduty": "nexus-aws-guardduty-connector",
}

def _connector_name(connector_dir):
    return os.path.basename(connector_dir)

def _read(*parts):
    with open(os.path.join(*parts)) as fh:
        return fh.read()

@pytest.fixture(scope="module")
def cloud_flow_mapping(nexus_toml_path):
    with open(nexus_toml_path, "rb") as fh:
        nexus = tomllib.load(fh)
    return nexus["schema_mappings"]["cloud_flow"]

# -----------------------------------------------------------------------------
# transmitter.rs / config.rs are byte-identical across all three crates
# -----------------------------------------------------------------------------

class TestTransmitterAndConfigAreSharedVerbatim:
    def test_sqs_messages_accessor_used_as_slice_not_option(self, connector_dir):
        """REAL BUG regression guard: main.rs originally pattern-matched
        `let Some(messages) = out.messages() else { continue };`, but
        aws-sdk-sqs 1.x's ReceiveMessageOutput::messages() returns `&[Message]`
        directly (an empty slice when there are none), not `Option<&[Message]>`
        -- a type mismatch (E0308) that broke `cargo check` for all three
        crates. Confirm the fixed source binds it as a plain slice and no
        longer wraps it in a refutable `Some(..) else` pattern."""
        src = _read(connector_dir, "src", "main.rs")
        assert "let messages = out.messages();" in src
        assert "let Some(messages) = out.messages()" not in src

    def test_transform_call_sites_pass_required_metadata_argument(self, aws_dir):
        """REAL BUG regression guard: guardduty/src/main.rs called
        `transformer.transform_finding(&finding)` with one argument, but
        transform_finding's signature (transformer.rs:47-51) requires a second
        `metadata: &HashMap<String, String>` -- E0061, broke `cargo check`.
        (The `aws-sdk-dynamodb` dependency is declared in guardduty's
        Cargo.toml, mirroring vpc/cloudtrail's metadata-lookup pattern, but no
        DynamoDB client / MetadataCache / fetch_metadata plumbing was ever
        wired up -- an incomplete port, not a typo.) Confirm every connector's
        transform call site now passes a metadata argument.
        """
        sigs = {
            "vpc": ("transform_row", _read(aws_dir, "vpc", "src", "main.rs")),
            "cloudtrail": ("transform_record", _read(aws_dir, "cloudtrail", "src", "main.rs")),
            "guardduty": ("transform_finding", _read(aws_dir, "guardduty", "src", "main.rs")),
        }
        for connector, (method, src) in sigs.items():
            m = re.search(rf"transformer\.{method}\(([^)]*)\)", src)
            assert m, f"{connector}: could not find transformer.{method}(...) call site"
            args = [a.strip() for a in m.group(1).split(",")]
            assert len(args) == 2, \
                f"{connector}: transformer.{method}({m.group(1)}) -- expected 2 arguments " \
                f"(record/finding, metadata), got {len(args)}"

    def test_guardduty_passes_empty_metadata_with_documented_rationale(self, aws_dir):
        # Narrower companion to the above: confirm guardduty's fix is the
        # documented "no DynamoDB plumbing exists, pass empty map" shape
        # (not e.g. a `&HashMap::new()` literal scattered with no explanation,
        # which would silently mask the missing-feature gap from future readers).
        src = _read(aws_dir, "guardduty", "src", "main.rs")
        assert "let empty_metadata: HashMap<String, String> = HashMap::new();" in src
        assert "transformer.transform_finding(&finding, &empty_metadata)" in src

    def test_transmitter_byte_identical_across_all_three_crates(self, aws_dir):
        vpc_src = _read(aws_dir, "vpc", "src", "transmitter.rs")
        for other in ("cloudtrail", "guardduty"):
            assert _read(aws_dir, other, "src", "transmitter.rs") == vpc_src, \
                f"{other}/src/transmitter.rs has drifted from vpc's -- HMAC formula, " \
                f"schema, or headers may now differ across connectors"

    def test_config_struct_shape_identical_aside_from_sensor_strings(self, aws_dir):
        # The only permitted differences between config.rs files are the
        # per-connector sensor_id default and sensor_type literal.
        vpc_src = _read(aws_dir, "vpc", "src", "config.rs")
        normalize = lambda s: re.sub(
            r'(sensor_id: env::var\("SENSOR_ID"\)\.unwrap_or_else\(\|_\| ")[^"]+("\.to_string\(\)\),\n\s*sensor_type: ")[^"]+(".to_string\(\))',
            r"\1<ID>\2<TYPE>\3", s,
        )
        normalized_vpc = normalize(vpc_src)
        for other in ("cloudtrail", "guardduty"):
            assert normalize(_read(aws_dir, other, "src", "config.rs")) == normalized_vpc, \
                f"{other}/src/config.rs has structurally drifted from vpc's beyond " \
                f"the expected sensor_id/sensor_type literals"

# -----------------------------------------------------------------------------
# Contract columns must actually be emitted by the real transmission schema
# -----------------------------------------------------------------------------

class TestContractColumnsPresentInSchema:
    def test_all_vector_columns_are_emitted(self, cloud_flow_mapping):
        missing = [c for c in cloud_flow_mapping["vector_columns"]
                   if c not in EXPECTED_AWS_PARQUET_COLUMNS]
        assert not missing, f"contract vector_columns not emitted by transmission schema: {missing}"

    def test_all_context_columns_are_emitted(self, cloud_flow_mapping):
        missing = [c for c in cloud_flow_mapping["context_columns"]
                   if c not in EXPECTED_AWS_PARQUET_COLUMNS]
        assert not missing, f"contract context_columns not emitted by transmission schema: {missing}"

    def test_identifier_primary_key_timestamp_sensor_id_columns_present(self, cloud_flow_mapping):
        for key in ("identifier_column", "primary_key_column", "timestamp_column", "sensor_id_column"):
            col = cloud_flow_mapping[key]
            assert col in EXPECTED_AWS_PARQUET_COLUMNS, \
                f"{key} = {col!r} is not an emitted Parquet column"

    def test_expected_column_count_and_order_matches_real_schema_definition(self, connector_dir):
        # Regression guard: extract Field::new(...) names+order+nullability
        # straight from the real to_parquet() Schema block so a future
        # column add/remove/reorder that isn't mirrored here fails loudly.
        src = _read(connector_dir, "src", "transmitter.rs")
        m = re.search(r"fn to_parquet\(.*?Schema::new\(vec!\[(.*?)\]\)\);", src, re.DOTALL)
        assert m, "could not locate to_parquet()'s Schema::new(vec![...]) block in transmitter.rs"
        fields = re.findall(r'Field::new\(\s*"([a-z0-9_]+)",\s*DataType::\w+,\s*(true|false)\)', m.group(1))
        names = [n for n, _ in fields]
        nullable = tuple(n for n, is_null in fields if is_null == "true")
        assert names == EXPECTED_AWS_PARQUET_COLUMNS
        assert len(names) == 31
        assert nullable == NULLABLE_COLUMNS

    def test_unified_flow_record_struct_field_order_matches_parquet_schema(self, connector_dir):
        # transformer.rs's UnifiedFlowRecord struct field order must match the
        # Parquet column order 1:1 -- Arrow's RecordBatch::try_new builds each
        # column array independently from `records.iter().map(|r| r.<field>)`,
        # so a struct/schema field-order mismatch would NOT be caught by the
        # type system; it would silently transpose column data on the wire.
        src = _read(connector_dir, "src", "transformer.rs")
        m = re.search(r"pub struct UnifiedFlowRecord \{(.*?)\n\}", src, re.DOTALL)
        assert m, "could not locate UnifiedFlowRecord struct definition"
        names = re.findall(r"pub (\w+):", m.group(1))
        assert names == EXPECTED_AWS_PARQUET_COLUMNS

# -----------------------------------------------------------------------------
# Sensor-type / sensor-id wire contract
# -----------------------------------------------------------------------------

class TestSensorTypeAndIdContract:
    def test_hardcoded_sensor_type_matches_mirror(self, connector_dir):
        name = _connector_name(connector_dir)
        src = _read(connector_dir, "src", "config.rs")
        assert f'sensor_type: "{WIRE_SENSOR_TYPE[name]}".to_string()' in src

    def test_default_sensor_id_matches_mirror(self, connector_dir):
        name = _connector_name(connector_dir)
        src = _read(connector_dir, "src", "config.rs")
        assert f'unwrap_or_else(|_| "{DEFAULT_SENSOR_ID[name]}".to_string())' in src

    def test_sensor_id_formula_is_pipe_delimited_triple(self, connector_dir):
        # All three connectors derive sensor_id as "{}|{}|{}" -- confirm the
        # mirror's sensor_id_for() matches that literal template (the specific
        # first component differs semantically: vpc_id vs account_id, but the
        # wire *shape* -- and thus core_ingress's parsing/keying of it -- is
        # identical across all three).
        src = _read(connector_dir, "src", "transformer.rs")
        assert 'format!("{}|{}|{}",' in src
        assert sensor_id_for("a", "b", "c") == "a|b|c"

    def test_wire_sensor_type_values_are_distinct_per_connector(self):
        values = list(WIRE_SENSOR_TYPE.values())
        assert len(values) == len(set(values)), "connectors must not share a wire X-Sensor-Type"

    def test_event_type_field_values_match_cloud_flow_identifier_column_routing(self, connector_dir, cloud_flow_mapping):
        # cloud_flow's identifier_column is "event_type" -- confirm each
        # connector actually stamps a literal event_type string (the value
        # nexus uses to route/identify these records within the cloud_flow
        # vector), and that "event_type" really is the mapping's identifier.
        assert cloud_flow_mapping["identifier_column"] == "event_type"
        src = _read(connector_dir, "src", "transformer.rs")
        assert re.search(r'event_type:\s*"[a-z_]+"\.to_string\(\)', src), \
            "connector does not stamp a literal event_type string into UnifiedFlowRecord"

# -----------------------------------------------------------------------------
# Content-Type / cloud_connector sensor profile
# -----------------------------------------------------------------------------

class TestContentTypeAndProfile:
    def test_content_type_is_parquet(self, connector_dir):
        src = _read(connector_dir, "src", "transmitter.rs")
        assert f'.header("Content-Type", "{CONTENT_TYPE}")' in src

    def test_cloud_connector_profile_documents_these_sensor_types(self, repo_root):
        # cloud_connector.toml is the documented sensor profile shared by
        # AWS/Azure cloud connectors -- its header comment must still list
        # the event_type strings these AWS connectors actually emit
        # (vpc_flow, cloudtrail_api, guardduty_finding), so a future rename
        # of any of those strings is caught here rather than silently
        # de-syncing the documented contract from the real wire values.
        profile = os.path.join(repo_root, "project_empros", "middleware", "config",
                               "sensor_profiles", "cloud_connector.toml")
        src = _read(profile)
        for event_type in ("vpc_flow", "cloudtrail_api", "guardduty_finding"):
            assert event_type in src, \
                f"cloud_connector.toml profile no longer documents event_type {event_type!r}"
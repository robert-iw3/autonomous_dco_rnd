"""
Tier-0 -- Schema-contract validation for the Nexus Azure connectors
(nexus-azure-nsg-connector, nexus-azure-activity-connector, nexus-azure-entraid-connector).
"""
import os
import re
import tomllib
import pytest

from azure_connectors_logic_mirror import (
    EXPECTED_AZURE_PARQUET_COLUMNS,
    NULLABLE_COLUMNS,
    WIRE_SENSOR_TYPE,
    DEFAULT_SENSOR_ID,
    CONTENT_TYPE,
    sensor_id_for_flow,
    sensor_id_for_entraid,
)

pytestmark = pytest.mark.tier0

CONNECTOR_CRATE_NAME = {
    "nsg": "nexus-azure-nsg-connector",
    "activity": "nexus-azure-activity-connector",
    "entraid": "nexus-azure-entraid-connector",
}

# src: infra/azure/{nsg,activity,entraid}/src/main.rs -- the transformer entry
# point each connector calls per inbound event/blob (signature/arity differs
# per connector: nsg takes a whole blob + metadata map and returns Vec<...>,
# activity takes a single event + metadata map and returns Option<...>,
# entraid takes a single event with NO metadata map -- Entra ID events carry
# tenant/category context inline, confirmed by reading transform_signin/
# transform_audit: no metadata.get(...) call exists anywhere in entraid's transformer).
TRANSFORM_ENTRY_POINT = {
    "nsg": ("transform_blob", 2),
    "activity": ("transform_event", 2),
    "entraid": ("transform_event", 1),
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
# transmitter.rs is byte-identical across all three crates; config.rs/cache.rs
# differ only in per-connector fields (storage_*/spool-bound fields vary) and
# string literals (sensor_id/sensor_type/event sources).
# -----------------------------------------------------------------------------

class TestTransmitterIsSharedVerbatim:
    def test_transmitter_byte_identical_across_all_three_crates(self, azure_dir):
        nsg_src = _read(azure_dir, "nsg", "src", "transmitter.rs")
        for other in ("activity", "entraid"):
            assert _read(azure_dir, other, "src", "transmitter.rs") == nsg_src, \
                f"{other}/src/transmitter.rs has drifted from nsg's -- HMAC formula, " \
                f"schema, or headers may now differ across connectors"

    def test_eventhubs_dependency_pinned_to_a_version_that_actually_exists(self, connector_dir):
        """REAL BUG regression guard: all three Cargo.toml files originally
        pinned `azure_messaging_eventhubs = "0.21"` -- a version that was NEVER
        published (crates.io's index tops out at 0.15.0 for that crate; `cargo
        check` failed immediately with "failed to select a version for the
        requirement... candidate versions found which didn't match: 0.15.0,
        0.14.0, ..." before compiling a single line of source). Every other
        `azure_*` dependency in these crates (azure_identity, azure_core,
        azure_storage_blobs, azure_data_tables) genuinely does publish 0.21.0
        -- this one crate isn't part of that lockstep release train and caps
        out lower, so a uniform "pin everything to 0.21" pass missed it.
        Confirm the pin now points at a version that resolves."""
        cargo_toml = _read(connector_dir, "Cargo.toml")
        m = re.search(r'azure_messaging_eventhubs\s*=\s*"([^"]+)"', cargo_toml)
        assert m, "could not find azure_messaging_eventhubs dependency line in Cargo.toml"
        pinned = m.group(1)
        assert pinned != "0.21", \
            "azure_messaging_eventhubs is pinned to 0.21, which was never published " \
            "(latest available is 0.15.0) -- cargo check fails before compiling any source"
        major, minor = (int(p) for p in pinned.lstrip("^~=").split(".")[:2])
        assert (major, minor) <= (0, 15), \
            f"azure_messaging_eventhubs pinned to {pinned!r} -- confirm this version " \
            f"actually exists on crates.io before lowering this bound (0.15.0 was the " \
            f"latest published at the time this regression guard was written)"

    def test_eventhubs_aliased_one_dot_oh_credential_deps_present(self, connector_dir):
        """REAL BUG regression guard: `azure_messaging_eventhubs` 0.15 requires
        `azure_core`/`azure_identity` 1.0 -- a structurally INCOMPATIBLE major
        line vs. the 0.21 line `azure_storage_blobs`/`azure_data_tables` are
        capped at (neither publishes any 1.x). The two `TokenCredential` traits
        differ (0.21's `get_token(scopes)` vs. 1.0's `get_token(scopes,
        options)`, with distinct `AccessToken` types), so a single credential
        object can't satisfy both -- cargo fails with "there are multiple
        different versions of crate azure_core in the dependency graph" (E0308)
        unless the 1.0 line is pulled in under a `package =` alias. Confirm
        Cargo.toml carries that alias (and the async-trait it requires to
        implement the 1.0-line TokenCredential trait for a custom chain)."""
        cargo_toml = _read(connector_dir, "Cargo.toml")
        assert re.search(r'azure_identity_eventhubs\s*=\s*\{\s*package\s*=\s*"azure_identity"\s*,\s*version\s*=\s*"1\.0"', cargo_toml), \
            "Cargo.toml is missing the aliased azure_identity 1.0 dependency " \
            "(azure_messaging_eventhubs 0.15 requires azure_identity 1.0, which " \
            "cannot coexist with the 0.21 line under the same crate name)"
        assert re.search(r'azure_core_eventhubs\s*=\s*\{\s*package\s*=\s*"azure_core"\s*,\s*version\s*=\s*"1\.0"', cargo_toml), \
            "Cargo.toml is missing the aliased azure_core 1.0 dependency"
        assert re.search(r'async-trait\s*=\s*"[^"]+"', cargo_toml), \
            "Cargo.toml is missing async-trait -- required to implement the " \
            "1.0-line TokenCredential trait for EventHubsCredentialChain"

    def test_eventhubs_credential_chain_module_exists_and_is_wired_in(self, connector_dir):
        """REAL BUG regression guard: `azure_identity` 1.0 REMOVED
        `DefaultAzureCredential`/`create_default_credential` outright (confirmed
        absent from its lib.rs `pub use` list -- only AzureCliCredential,
        ManagedIdentityCredential, DeveloperToolsCredential, etc. remain), so
        the Event Hubs consumer can't reuse the 0.21-line default-credential
        helper the blob/table clients use. Confirm each connector defines (and
        actually constructs/passes) its own EventHubsCredentialChain rather
        than silently falling back to a 0.21-line credential that would trip
        the cross-major-version E0308 mismatch at the `.open(...)` call site."""
        name = _connector_name(connector_dir)
        cred_src = _read(connector_dir, "src", "eventhubs_credential.rs")
        assert "pub struct EventHubsCredentialChain" in cred_src, \
            f"{name}: eventhubs_credential.rs no longer defines EventHubsCredentialChain"
        assert re.search(r"impl TokenCredential for EventHubsCredentialChain", cred_src), \
            f"{name}: EventHubsCredentialChain no longer implements the 1.0-line TokenCredential trait"
        assert "ManagedIdentityCredential" in cred_src and "DeveloperToolsCredential" in cred_src, \
            f"{name}: EventHubsCredentialChain no longer chains ManagedIdentityCredential -> DeveloperToolsCredential"

        main_src = _read(connector_dir, "src", "main.rs")
        assert "mod eventhubs_credential;" in main_src, \
            f"{name}: main.rs no longer declares the eventhubs_credential module"
        assert re.search(r"EventHubsCredentialChain::new\(\)\?", main_src), \
            f"{name}: main.rs no longer constructs an EventHubsCredentialChain for the Event Hubs consumer"

    def test_consumer_uses_real_builder_open_api_not_fictional_connection_string_ctor(self, connector_dir):
        """REAL BUG regression guard: the original code assumed a fictional
        `ConsumerClient::new(connection_str, name, group, opts)` constructor and
        a `config.eventhub_connection_str`/EVENTHUB_CONNECTION_STRING field --
        `azure_messaging_eventhubs` 0.15 never supported connection-string auth
        (only `(fully_qualified_namespace: &str, credential)`); the real ctor is
        the private `ConsumerClient::new` reached only via
        `ConsumerClient::builder().with_consumer_group(...).open(namespace, name,
        credential).await`. Confirm main.rs uses the real builder/open shape and
        config.rs carries `eventhub_namespace`/EVENTHUB_NAMESPACE rather than
        the fictional connection-string field."""
        name = _connector_name(connector_dir)
        main_src = _read(connector_dir, "src", "main.rs")
        assert "ConsumerClient::builder()" in main_src, \
            f"{name}: main.rs does not build the consumer via ConsumerClient::builder() " \
            f"(0.15 has no connection-string constructor)"
        assert re.search(r"\.with_consumer_group\(config\.consumer_group\.clone\(\)\)\s*\n?\s*\.open\(", main_src), \
            f"{name}: main.rs does not chain .with_consumer_group(...).open(...) on the builder"
        assert re.search(r"\.open\(&config\.eventhub_namespace,\s*config\.eventhub_name\.clone\(\),", main_src), \
            f"{name}: main.rs does not open the consumer with (namespace, name, credential) -- " \
            f"the only auth shape azure_messaging_eventhubs 0.15 actually supports"

        config_src = _read(connector_dir, "src", "config.rs")
        assert "pub eventhub_namespace: String" in config_src, \
            f"{name}: config.rs is missing eventhub_namespace (still assumes connection-string auth?)"
        assert 'env::var("EVENTHUB_NAMESPACE")' in config_src, \
            f"{name}: config.rs does not read EVENTHUB_NAMESPACE from the environment"
        assert "eventhub_connection_str" not in config_src and "EVENTHUB_CONNECTION_STRING" not in config_src, \
            f"{name}: config.rs still references the fictional connection-string field/env-var"

    def test_consumer_discovers_partitions_and_streams_via_real_015_methods(self, connector_dir):
        """REAL BUG regression guard: the original code called
        `consumer.get_partition_ids()` (E0599 -- doesn't exist) and
        `consumer.read_events_from_partition(&id, opts)` on a `Clone`d consumer
        (E0599/E0624 -- ConsumerClient isn't Clone). The real 0.15 shapes are
        `consumer.get_eventhub_properties().await?.partition_ids`, an
        `Arc`-wrapped consumer cloned via `Arc::clone`, and per-partition
        `consumer.open_receiver_on_partition(id, opts).await?.stream_events()`."""
        name = _connector_name(connector_dir)
        main_src = _read(connector_dir, "src", "main.rs")
        assert "get_eventhub_properties().await?.partition_ids" in main_src, \
            f"{name}: main.rs does not discover partitions via get_eventhub_properties().partition_ids"
        assert "Arc::clone(&consumer)" in main_src, \
            f"{name}: main.rs does not Arc::clone the shared consumer per-partition (ConsumerClient isn't Clone)"
        assert re.search(r"\.open_receiver_on_partition\(partition_id\.clone\(\),[^;]*?\)\.await", main_src), \
            f"{name}: main.rs does not open a per-partition receiver via open_receiver_on_partition(...)"
        assert ".stream_events()" in main_src, \
            f"{name}: main.rs does not stream events via receiver.stream_events()"

    def test_event_body_accessed_through_received_event_data_indirection(self, connector_dir):
        """REAL BUG regression guard: `ReceivedEventData` (the type yielded by
        `stream_events()`) has no `.body()` of its own (E0599) -- the raw bytes
        live on the inner `EventData`, reachable only via
        `received.event_data().body()`. A direct `received.body()` call compiles
        right up until `cargo check` on the real crate, since Tier 0's
        string-mirroring can't catch a missing-method error -- this guards the
        real method-chain shape."""
        name = _connector_name(connector_dir)
        main_src = _read(connector_dir, "src", "main.rs")
        assert re.search(r"event_data\.event_data\(\)\.body\(\)", main_src), \
            f"{name}: main.rs does not access the event body via " \
            f"event_data.event_data().body() -- ReceivedEventData has no .body() of its own"

    def test_config_carries_spool_bound_fields_required_by_shared_transmitter(self, connector_dir):
        """REAL BUG regression guard: entraid's config.rs was missing
        `max_spool_bytes`/`max_spool_files`/`spool_replay` -- fields the shared
        (byte-identical) transmitter.rs unconditionally reads off `self.config`.
        nsg/activity both declared them; entraid's struct silently lacked all
        three, so `cargo check` failed with three E0609 "no field ... on type
        Config" errors only once the rest of the consumer-rewrite chain cleared.
        A Tier-0 string-mirror wouldn't catch this -- only a per-connector
        struct-completeness check does."""
        name = _connector_name(connector_dir)
        config_src = _read(connector_dir, "src", "config.rs")
        for field, env_fn in (
            ("max_spool_bytes", "u64"),
            ("max_spool_files", "usize"),
            ("spool_replay", "bool"),
        ):
            assert f"pub {field}: {env_fn}" in config_src, \
                f"{name}: config.rs Config struct is missing `pub {field}: {env_fn}` " \
                f"-- transmitter.rs (shared verbatim across all 3 connectors) reads self.config.{field}"

    def test_partition_checkpoint_persisted_only_after_confirmed_transmit(self, connector_dir):
        """Restart-safety guard: on restart the consumer must resume from the
        last *confirmed-transmitted* offset rather than the Event Hub's default
        (latest) position -- otherwise events that arrived while the connector
        was down are silently lost. Confirm each connector wires a
        PartitionCheckpoint: loads a prior offset to seed `start_position`
        before opening each partition's receiver, and persists the new offset
        ONLY inside the success arm of `spool_and_transmit(...).await`, never
        unconditionally (an unconditional save would let a failed transmit's
        events be skipped on the next restart -- silent data loss in the other
        direction)."""
        name = _connector_name(connector_dir)
        main_src = _read(connector_dir, "src", "main.rs")
        assert "mod checkpoint;" in main_src, f"{name}: main.rs no longer declares the checkpoint module"
        assert "PartitionCheckpoint::new(&config.spool_dir)" in main_src, \
            f"{name}: main.rs no longer constructs a PartitionCheckpoint over the spool directory"
        assert re.search(r"checkpoint\.load\(&partition_id\)", main_src), \
            f"{name}: main.rs no longer loads a persisted checkpoint to seed the receiver's start_position"
        assert "StartLocation::Offset(offset)" in main_src, \
            f"{name}: main.rs no longer seeds OpenReceiverOptions.start_position from the loaded checkpoint offset"

        # The save call must be reachable only from the success arm of a
        # spool_and_transmit(...) check -- i.e. gated behind a truthiness test
        # on its result, not a bare unconditional `checkpoint.save(...)`.
        save_sites = list(re.finditer(r"checkpoint\.save\(&partition_id,", main_src))
        assert save_sites, f"{name}: main.rs never persists a confirmed-transmitted checkpoint offset"
        for site in save_sites:
            preceding = main_src[:site.start()]
            # Walk back to the nearest `if`/`if let ... =` guarding this save call;
            # it must test a spool_and_transmit(...) outcome (directly, or via a
            # `flush(...)` helper whose own success the surrounding `if` checks).
            guard_window = preceding[-400:]
            assert re.search(r"spool_and_transmit\([^)]*\)\.await\s*\{", guard_window) or \
                   re.search(r"flush\([^)]*\)\.await\s*\n?\s*\{", guard_window), \
                f"{name}: checkpoint.save(...) at offset {site.start()} is not visibly " \
                f"gated on a spool_and_transmit/flush success -- could persist past lost events"

    def test_transform_entry_point_arity_matches_documented_shape(self, connector_dir):
        """REAL BUG class regression guard (the same class as infra/aws's guardduty
        E0061 -- a transform call site with the wrong arity silently breaks
        `cargo check`, not Tier 0's string mirroring): confirm each connector's
        main.rs invokes its transformer's entry point with the documented
        argument count -- nsg/activity take (event_or_blob, &metadata), entraid
        takes (event) only (it has no metadata-cache plumbing; tenant/category
        context arrives inline in the event payload itself)."""
        name = _connector_name(connector_dir)
        method, expected_arity = TRANSFORM_ENTRY_POINT[name]
        main_src = _read(connector_dir, "src", "main.rs")
        m = re.search(rf"transformer\.{method}\(([^)]*)\)", main_src)
        assert m, f"{name}: could not find transformer.{method}(...) call site in main.rs"
        args = [a.strip() for a in m.group(1).split(",") if a.strip()]
        assert len(args) == expected_arity, \
            f"{name}: transformer.{method}({m.group(1)}) -- expected {expected_arity} " \
            f"argument(s), got {len(args)}"

        # Cross-check: the transformer's own fn signature must declare the same
        # arity. Params are matched as `name: &?Type[<generic, args>]` so a
        # `HashMap<String, String>`'s internal comma isn't mistaken for a
        # parameter separator (a naive split(",") would over-count by one).
        transformer_src = _read(connector_dir, "src", "transformer.rs")
        sig_m = re.search(rf"pub fn {method}\(\s*&self,(.*?)\)\s*(?:->|\{{)", transformer_src, re.DOTALL)
        assert sig_m, f"{name}: could not find pub fn {method}(&self, ...) signature in transformer.rs"
        sig_params = re.findall(r"(\w+):\s*&?[\w:]+(?:<[^>]*>)?", sig_m.group(1))
        assert len(sig_params) == expected_arity, \
            f"{name}: pub fn {method}(&self, {sig_m.group(1)}) declares {len(sig_params)} " \
            f"param(s) ({sig_params}), but main.rs calls it with {expected_arity} argument(s) -- arity mismatch"

# -----------------------------------------------------------------------------
# Contract columns must actually be emitted by the real transmission schema
# -----------------------------------------------------------------------------

class TestContractColumnsPresentInSchema:
    def test_all_vector_columns_are_emitted(self, cloud_flow_mapping):
        missing = [c for c in cloud_flow_mapping["vector_columns"]
                   if c not in EXPECTED_AZURE_PARQUET_COLUMNS]
        assert not missing, f"contract vector_columns not emitted by transmission schema: {missing}"

    def test_all_context_columns_are_emitted(self, cloud_flow_mapping):
        missing = [c for c in cloud_flow_mapping["context_columns"]
                   if c not in EXPECTED_AZURE_PARQUET_COLUMNS]
        assert not missing, f"contract context_columns not emitted by transmission schema: {missing}"

    def test_identifier_primary_key_timestamp_sensor_id_columns_present(self, cloud_flow_mapping):
        for key in ("identifier_column", "primary_key_column", "timestamp_column", "sensor_id_column"):
            col = cloud_flow_mapping[key]
            assert col in EXPECTED_AZURE_PARQUET_COLUMNS, \
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
        assert names == EXPECTED_AZURE_PARQUET_COLUMNS
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
        assert names == EXPECTED_AZURE_PARQUET_COLUMNS

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

    def test_sensor_id_formula_matches_documented_shape_per_connector(self, connector_dir):
        """nsg/activity derive sensor_id as subscription_id|environment|region
        (the SAME pipe-delimited-triple wire *shape* infra/aws uses, just keyed
        on subscription_id rather than account/vpc_id -- core_ingress parses/keys
        on the shape, not the semantic meaning of each component). entraid's
        formula is STRUCTURALLY DIFFERENT: tenant_id|entraid|<signin|audit> --
        confirmed not a bug by reading transform_signin/transform_audit, which
        carry no environment/region lookup (Entra ID is tenant-, not
        subscription-scoped, so there is nothing to look up)."""
        name = _connector_name(connector_dir)
        src = _read(connector_dir, "src", "transformer.rs")
        if name in ("nsg", "activity"):
            assert 'format!("{}|{}|{}", subscription_id, environment, region)' in src
            assert sensor_id_for_flow("sub", "env", "region") == "sub|env|region"
        else:
            assert 'format!("{}|entraid|signin", tenant_id)' in src
            assert 'format!("{}|entraid|audit", tenant_id)' in src
            assert sensor_id_for_entraid("tenant", "signin") == "tenant|entraid|signin"
            assert sensor_id_for_entraid("tenant", "audit") == "tenant|entraid|audit"

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
        assert re.search(r'event_type:\s*"[a-z_]+"\.to_string\(\)', src) or \
               re.search(r'event_type:\s*event_type\.to_string\(\)', src), \
            "connector does not stamp a literal (or locally-derived literal) event_type string into UnifiedFlowRecord"

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
        # the event_type strings these Azure connectors actually emit
        # (nsg_flow, azure_activity, entraid_signin), so a future rename of
        # any of those strings is caught here rather than silently de-syncing
        # the documented contract from the real wire values.
        profile = os.path.join(repo_root, "project_empros", "middleware", "config",
                               "sensor_profiles", "cloud_connector.toml")
        src = _read(profile)
        for event_type in ("nsg_flow", "azure_activity", "entraid_signin"):
            assert event_type in src, \
                f"cloud_connector.toml profile no longer documents event_type {event_type!r}"
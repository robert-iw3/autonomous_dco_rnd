"""
Tier-2 -- IaC <-> connector runtime-contract conformance for Azure.
"""
import pytest
import iac_deploy_mirror as M
import azure_connectors_logic_mirror as CM  # tier0 connector mirror (on sys.path via root conftest)
import _iac_parse as P

pytestmark = pytest.mark.tier2

class TestEventHubAccessPolicy:
    def test_listener_auth_rule_grants_only_listen(self, tf_src, connector_name):
        """The Nexus consumer must bind a listen-only authorization rule --
        no send, no manage. Analogous to the AWS IAM least-privilege check:
        the connector calls only Event Hub Receive operations at runtime."""
        listen_rules = [
            (name, body)
            for name, body in P.iter_resources(tf_src, "azurerm_eventhub_authorization_rule")
            if P.scalar(body, "listen") == "true"
        ]
        assert listen_rules, (
            f"{connector_name}: no listen=true azurerm_eventhub_authorization_rule found"
        )
        for name, body in listen_rules:
            assert P.scalar(body, "send") == "false", (
                f"{connector_name}: auth rule {name} -- listen=true but send=true "
                f"(connector only reads; send permission is an over-grant)"
            )
            assert P.scalar(body, "manage") == "false", (
                f"{connector_name}: auth rule {name} -- listen=true but manage=true "
                f"(connector only reads; manage permission is an over-grant)"
            )

    def test_send_auth_rule_provisioned_for_push_connectors(self, tf_src, connector_name):
        """activity/entraid: a send=true auth rule must exist so the Azure
        Diagnostic Setting can authenticate to write events into the Event Hub.
        Without this rule the diagnostic setting resource is created but events
        will never flow -- there is no deployment-time error, only a silent gap."""
        profile = M.CONNECTOR_PROFILE.get(connector_name, {})
        if not profile.get("diagnostic_resource_type"):
            pytest.skip(f"{connector_name}: does not push via Diagnostic Setting (nsg uses EventGrid)")
        send_rules = [
            name for name, body in P.iter_resources(tf_src, "azurerm_eventhub_authorization_rule")
            if P.scalar(body, "send") == "true"
        ]
        assert send_rules, (
            f"{connector_name}: no send=true azurerm_eventhub_authorization_rule found -- "
            f"the Diagnostic Setting cannot authenticate to write events into Event Hub"
        )

    def test_diagnostic_setting_references_send_capable_rule(self, tf_src, connector_name):
        """The eventhub_authorization_rule_id in the Diagnostic Setting must reference
        a send-capable rule. If it references the listen-only nexus consumer rule the
        resource is created and apply succeeds, but every write returns 403 and no
        events reach the hub."""
        profile = M.CONNECTOR_PROFILE.get(connector_name, {})
        rtype = profile.get("diagnostic_resource_type")
        if not rtype:
            pytest.skip(f"{connector_name}: no diagnostic setting (nsg uses EventGrid)")
        settings = list(P.iter_resources(tf_src, rtype))
        if not settings:
            pytest.skip(f"{connector_name}: no {rtype} found")
        for name, body in settings:
            ref = P.ref_scalar(body, "eventhub_authorization_rule_id")
            assert ref is not None, (
                f"{connector_name}: {rtype}.{name} has no eventhub_authorization_rule_id reference"
            )
            # Must point at the send rule, never the listen rule
            assert ref.endswith(".send"), (
                f"{connector_name}: {rtype}.{name}.eventhub_authorization_rule_id = {ref!r} "
                f"does not reference the send rule -- if this points to the listen rule "
                f"every write to Event Hub will 403 silently"
            )
            # That rule must actually be defined in this stack with send=true
            send_val = P.auth_rule_scalar(tf_src, ref.split(".")[-1], "send")
            assert send_val == "true", (
                f"{connector_name}: {ref!r} referenced by {rtype}.{name} does not have "
                f"send = true in this stack"
            )

    def test_consumer_group_is_provisioned(self, tf_src, connector_name):
        """Each connector needs its own consumer group so its checkpoint offset
        is independent of other consumers on the same hub."""
        profile = M.CONNECTOR_PROFILE.get(connector_name)
        if not profile:
            pytest.skip(f"{connector_name}: no profile")
        groups = list(P.iter_resources(tf_src, "azurerm_eventhub_consumer_group"))
        assert groups, f"{connector_name}: no azurerm_eventhub_consumer_group found"
        names = {P.scalar(body, "name") for _, body in groups}
        assert profile["consumer_group"] in names, (
            f"{connector_name}: expected consumer group {profile['consumer_group']!r} "
            f"not found; provisioned: {sorted(names)}"
        )

class TestEventSourceBinding:
    def test_nsg_has_eventgrid_blob_to_eventhub_subscription(self, tf_src, connector_name):
        """nsg: blob-created events on the NSG flow-log storage account must be
        routed to the Event Hub via an Event Grid system topic subscription.
        Analogous to the AWS S3 bucket notification filter_suffix check --
        the event source wiring must be explicit in the IaC, not manual."""
        profile = M.CONNECTOR_PROFILE.get(connector_name, {})
        if not profile.get("has_eventgrid"):
            pytest.skip(f"{connector_name}: does not use Event Grid routing")
        topics = list(P.iter_resources(tf_src, "azurerm_eventgrid_system_topic"))
        assert topics, f"{connector_name}: no azurerm_eventgrid_system_topic found"
        subs = list(P.iter_resources(tf_src, "azurerm_eventgrid_system_topic_event_subscription"))
        assert subs, (
            f"{connector_name}: no azurerm_eventgrid_system_topic_event_subscription found "
            f"(blob events are not routed to the Event Hub)"
        )
        blob_create_subs = [
            name for name, body in subs
            if "Microsoft.Storage.BlobCreated" in body
        ]
        assert blob_create_subs, (
            f"{connector_name}: Event Grid subscription does not include "
            f"Microsoft.Storage.BlobCreated -- NSG flow logs will not trigger the connector"
        )

    def test_nsg_eventgrid_subject_filter_targets_nsg_container(self, tf_src, connector_name):
        """The EventGrid subscription subject_begins_with must contain the exact NSG
        flow-log container path. If it drifts from the storage container resource name
        blob-created events stop routing and the connector receives nothing."""
        profile = M.CONNECTOR_PROFILE.get(connector_name, {})
        if not profile.get("has_eventgrid"):
            pytest.skip(f"{connector_name}: does not use Event Grid routing")
        # EventGrid subscription body must reference the canonical container name
        subs = list(P.iter_resources(tf_src, "azurerm_eventgrid_system_topic_event_subscription"))
        assert subs, f"{connector_name}: no EventGrid subscription"
        for name, body in subs:
            assert M.NSG_FLOW_LOG_CONTAINER in body, (
                f"{connector_name}: EventGrid subscription {name} subject_begins_with "
                f"does not contain {M.NSG_FLOW_LOG_CONTAINER!r} -- NSG flow log blobs "
                f"will not match the filter and the connector will never be triggered"
            )
        # Cross-check: the storage container resource name must also match
        container_names = {
            P.scalar(body, "name")
            for _, body in P.iter_resources(tf_src, "azurerm_storage_container")
        }
        assert M.NSG_FLOW_LOG_CONTAINER in container_names, (
            f"{connector_name}: azurerm_storage_container name does not match "
            f"NSG_FLOW_LOG_CONTAINER={M.NSG_FLOW_LOG_CONTAINER!r} "
            f"(found: {sorted(container_names)}) -- filter and container have drifted apart"
        )

    def test_nsg_has_infrastructure_metadata_table(self, tf_src, connector_name):
        """The NSG connector looks up infrastructure metadata (VPC/subnet context)
        from Table Storage at runtime. A missing table causes the connector to crash
        on startup with a 404 -- the Terraform must provision it."""
        profile = M.CONNECTOR_PROFILE.get(connector_name, {})
        if not profile.get("has_storage"):
            pytest.skip(f"{connector_name}: does not use Storage (no metadata table expected)")
        tables = list(P.iter_resources(tf_src, "azurerm_storage_table"))
        assert tables, (
            f"{connector_name}: no azurerm_storage_table found -- the connector requires "
            f"Table Storage for infrastructure metadata lookup on startup"
        )

    def test_nsg_eventgrid_endpoint_references_hub_in_this_stack(self, tf_src, connector_name):
        """The EventGrid subscription eventhub_endpoint_id must be a reference to an
        azurerm_eventhub resource defined in this stack. A hardcoded string or a
        reference to a hub in a different stack would silently route events to the
        wrong destination and is not verified by terraform validate."""
        profile = M.CONNECTOR_PROFILE.get(connector_name, {})
        if not profile.get("has_eventgrid"):
            pytest.skip(f"{connector_name}: does not use Event Grid routing")
        subs = list(P.iter_resources(tf_src, "azurerm_eventgrid_system_topic_event_subscription"))
        assert subs, f"{connector_name}: no EventGrid subscription"
        defined = P.resource_addresses(tf_src)
        for name, body in subs:
            ref = P.ref_scalar(body, "eventhub_endpoint_id")
            assert ref is not None, (
                f"{connector_name}: EventGrid subscription {name} eventhub_endpoint_id "
                f"is not a Terraform reference to an azurerm_eventhub in this stack"
            )
            assert ref in defined, (
                f"{connector_name}: EventGrid subscription {name} eventhub_endpoint_id "
                f"references {ref!r} which is not defined in this stack "
                f"(defined: {sorted(a for a in defined if 'eventhub' in a)})"
            )

    def test_activity_diagnostic_setting_covers_required_categories(self, tf_src, connector_name):
        """activity: the Diagnostic Setting must stream all three required
        log categories (Administrative, Security, Policy) into the Event Hub."""
        profile = M.CONNECTOR_PROFILE.get(connector_name, {})
        rtype = profile.get("diagnostic_resource_type")
        if rtype != "azurerm_monitor_diagnostic_setting":
            pytest.skip(f"{connector_name}: does not use azurerm_monitor_diagnostic_setting")
        settings = list(P.iter_resources(tf_src, rtype))
        assert settings, f"{connector_name}: no {rtype} found"
        present = P.diagnostic_log_categories(tf_src, rtype)
        required = profile["required_log_categories"]
        missing = required - present
        assert not missing, (
            f"{connector_name}: diagnostic setting missing required log categories {sorted(missing)} "
            f"(present: {sorted(present)})"
        )

    def test_entraid_aad_diagnostic_setting_covers_required_categories(self, tf_src, connector_name):
        """entraid: the AAD Diagnostic Setting must stream all five sign-in and
        audit log categories into the Event Hub."""
        profile = M.CONNECTOR_PROFILE.get(connector_name, {})
        rtype = profile.get("diagnostic_resource_type")
        if rtype != "azurerm_monitor_aad_diagnostic_setting":
            pytest.skip(f"{connector_name}: does not use azurerm_monitor_aad_diagnostic_setting")
        settings = list(P.iter_resources(tf_src, rtype))
        assert settings, f"{connector_name}: no {rtype} found"
        present = P.diagnostic_log_categories(tf_src, rtype)
        required = profile["required_log_categories"]
        missing = required - present
        assert not missing, (
            f"{connector_name}: AAD diagnostic setting missing required log categories {sorted(missing)} "
            f"(present: {sorted(present)})"
        )

class TestOutputsContract:
    def test_all_required_outputs_declared(self, tf_src, connector_name):
        """outputs.tf must export every value the runtime config reads at deploy time.
        A missing output fails silently: the connector starts but uses a stale or empty
        value for the connection string, hub name, or storage URL."""
        required = M.REQUIRED_OUTPUTS.get(connector_name)
        if not required:
            pytest.skip(f"{connector_name}: no required outputs defined")
        declared = P.output_names(tf_src)
        missing = required - declared
        assert not missing, (
            f"{connector_name}: outputs.tf is missing required outputs {sorted(missing)}; "
            f"declared: {sorted(declared)}"
        )

    def test_connection_string_output_bound_to_listen_rule(self, tf_src, connector_name):
        """eventhub_connection_string must reference the listen-only rule's
        primary_connection_string. If it accidentally references the send rule the
        connector is provisioned with write access to the Event Hub -- a least-
        privilege violation that would not fail at deploy time."""
        if "eventhub_connection_string" not in P.output_names(tf_src):
            pytest.skip(f"{connector_name}: no eventhub_connection_string output")
        ref = P.output_ref(tf_src, "eventhub_connection_string")
        assert ref is not None, (
            f"{connector_name}: could not parse eventhub_connection_string output value"
        )
        assert ref == "azurerm_eventhub_authorization_rule.listen", (
            f"{connector_name}: eventhub_connection_string references {ref!r} -- "
            f"expected azurerm_eventhub_authorization_rule.listen "
            f"(the connector must receive a listen-only connection string)"
        )

class TestManagedIdentityWiring:
    def test_identity_has_eventhub_data_receiver_role(self, tf_src, connector_name):
        """The connector's managed identity must have the Azure Event Hubs Data Receiver
        role assignment -- without it the identity can authenticate but cannot receive
        events from the hub, failing at runtime with a 401."""
        role_assignments = list(P.iter_resources(tf_src, "azurerm_role_assignment"))
        assert role_assignments, f"{connector_name}: no azurerm_role_assignment found"
        receiver_roles = [
            (name, body) for name, body in role_assignments
            if "Data Receiver" in body
        ]
        assert receiver_roles, (
            f"{connector_name}: no azurerm_role_assignment granting 'Azure Event Hubs Data Receiver' -- "
            f"the connector identity cannot receive from Event Hub at runtime"
        )

    def test_identity_has_key_vault_secrets_user_role(self, tf_src, connector_name):
        """The connector's managed identity must have the Key Vault Secrets User role
        to read the auth_token secret at startup. Missing this causes a 403 when
        the connector calls GetSecret on first run."""
        role_assignments = list(P.iter_resources(tf_src, "azurerm_role_assignment"))
        kv_reader_roles = [
            (name, body) for name, body in role_assignments
            if "Secrets User" in body or "Key Vault Secrets" in body
        ]
        assert kv_reader_roles, (
            f"{connector_name}: no Key Vault Secrets User role assignment found -- "
            f"the connector identity cannot read the auth_token secret at startup"
        )

class TestConnectorEgressIsParquet:
    def test_connector_egress_is_still_parquet(self):
        """Independent fact (not tied to the ingest side): the connector's
        egress to Nexus is Parquet. Guards against the tier0 contract drifting."""
        assert CM.CONTENT_TYPE == "application/vnd.apache.parquet"
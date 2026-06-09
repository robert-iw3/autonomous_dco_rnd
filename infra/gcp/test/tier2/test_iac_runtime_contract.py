"""
Tier-2 -- Runtime-contract static checks for the GCP deploy/ stacks.

These tests parse the Terraform source without executing it to verify that
each connector's IaC wires its resources together correctly.
"""
import sys
import os
import pytest

import iac_deploy_mirror as M
import _iac_parse as P

pytestmark = pytest.mark.tier2

# ---------------------------------------------------------------------------
# Pub/Sub subscription → topic binding
# ---------------------------------------------------------------------------
class TestPubSubBinding:
    def test_subscription_topic_references_stack_topic(self, tf_src, connector_name):
        """The subscription's topic attribute must reference the topic provisioned
        in the same stack, not a hardcoded name or a cross-stack reference that
        would allow the subscription to silently drain the wrong topic."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        sub_name = profile["subscription_tf_name"]
        topic_tf_name = profile["topic_tf_name"]

        subs = list(P.iter_resources(tf_src, "google_pubsub_subscription"))
        body = next((b for n, b in subs if n == sub_name), None)
        assert body is not None, f"{connector_name}: subscription {sub_name!r} not found"

        ref = P.ref_scalar(body, "topic")
        assert ref is not None, (
            f"{connector_name}: subscription {sub_name!r} has no topic reference"
        )
        expected_prefix = f"google_pubsub_topic.{topic_tf_name}"
        assert ref.startswith(expected_prefix) or ref == expected_prefix, (
            f"{connector_name}: {sub_name}.topic = {ref!r}; "
            f"expected a reference starting with {expected_prefix!r}"
        )

    def test_topic_resource_is_declared(self, tf_src, connector_name):
        """The topic the subscription references must actually be declared in
        this stack. A dangling reference only fails at apply time."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        addr = f"google_pubsub_topic.{profile['topic_tf_name']}"
        assert addr in P.resource_addresses(tf_src), (
            f"{connector_name}: resource {addr!r} not declared in this stack"
        )

# ---------------------------------------------------------------------------
# IAM publisher binding (audit + vpc)
# ---------------------------------------------------------------------------
class TestSinkIAMBinding:
    def test_iam_member_grants_publisher_role(self, tf_src, connector_name):
        """The google_pubsub_topic_iam_member must grant roles/pubsub.publisher.
        Any other role is either too permissive (owner/editor) or too restrictive
        (viewer) to allow the logging sink to deliver messages."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["has_logging_sink"]:
            pytest.skip(f"{connector_name}: no logging sink / IAM binding required")

        iam_resources = list(P.iter_resources(tf_src, "google_pubsub_topic_iam_member"))
        assert iam_resources, (
            f"{connector_name}: no google_pubsub_topic_iam_member found"
        )
        _, body = iam_resources[0]
        role = P.scalar(body, "role")
        assert role == "roles/pubsub.publisher", (
            f"{connector_name}: IAM member role = {role!r}; "
            f"expected 'roles/pubsub.publisher'"
        )

    def test_iam_member_references_sink_writer_identity(self, tf_src, connector_name):
        """The IAM member's member attribute must reference the sink's
        writer_identity (the service account GCP auto-creates per unique sink).
        A hardcoded service account would lose the binding if the sink is
        re-created."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["has_logging_sink"]:
            pytest.skip(f"{connector_name}: no logging sink / IAM binding required")

        sink_tf_name = profile["sink_tf_name"]
        iam_resources = list(P.iter_resources(tf_src, "google_pubsub_topic_iam_member"))
        assert iam_resources, f"{connector_name}: no google_pubsub_topic_iam_member found"
        _, body = iam_resources[0]

        expected_fragment = f"google_logging_project_sink.{sink_tf_name}"
        assert expected_fragment in body, (
            f"{connector_name}: IAM member.member does not reference "
            f"{expected_fragment!r}; body snippet:\n{body[:400]}"
        )

    def test_iam_unique_writer_identity_enabled(self, tf_src, connector_name):
        """unique_writer_identity = true gives each sink its own service account.
        Without it, all sinks share a default account and a compromised sink
        can publish to any topic that account has access to."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["has_logging_sink"]:
            pytest.skip(f"{connector_name}: no logging sink")

        sink_tf_name = profile["sink_tf_name"]
        sinks = list(P.iter_resources(tf_src, "google_logging_project_sink"))
        body = next((b for n, b in sinks if n == sink_tf_name), None)
        assert body is not None, (
            f"{connector_name}: logging sink {sink_tf_name!r} not found"
        )
        val = P.scalar(body, "unique_writer_identity")
        assert val == "true", (
            f"{connector_name}: {sink_tf_name}.unique_writer_identity = {val!r}; "
            f"expected 'true'"
        )

# ---------------------------------------------------------------------------
# SCC notification config (scc only)
# ---------------------------------------------------------------------------
class TestSCCNotificationConfig:
    def test_notification_config_exists(self, tf_src, connector_name):
        """scc connector must provision a google_scc_notification_config to route
        findings to Pub/Sub. Without it the subscription never receives messages."""
        if not M.CONNECTOR_PROFILE[connector_name]["has_scc_notification"]:
            pytest.skip(f"{connector_name}: no SCC notification config required")
        configs = list(P.iter_resources(tf_src, "google_scc_notification_config"))
        assert configs, (
            f"{connector_name}: no google_scc_notification_config found"
        )

    def test_pubsub_topic_references_stack_topic(self, tf_src, connector_name):
        """The notification config's pubsub_topic must reference the scc_findings
        topic in this stack. A cross-stack or hardcoded reference breaks the
        routing contract."""
        if not M.CONNECTOR_PROFILE[connector_name]["has_scc_notification"]:
            pytest.skip(f"{connector_name}: no SCC notification config required")
        profile = M.CONNECTOR_PROFILE[connector_name]
        configs = list(P.iter_resources(tf_src, "google_scc_notification_config"))
        assert configs, f"{connector_name}: no google_scc_notification_config found"
        _, body = configs[0]
        ref = P.ref_scalar(body, "pubsub_topic")
        expected_prefix = f"google_pubsub_topic.{profile['topic_tf_name']}"
        assert ref is not None and ref.startswith(expected_prefix), (
            f"{connector_name}: scc_notification.pubsub_topic = {ref!r}; "
            f"expected reference to {expected_prefix!r}"
        )

    def test_streaming_config_filter_is_active_only(self, tf_src, connector_name):
        """The streaming_config filter must be scoped to ACTIVE findings. Without
        this guard, inactive/resolved findings flood the topic and the connector's
        dedup cache cannot distinguish them from new events."""
        if not M.CONNECTOR_PROFILE[connector_name]["has_scc_notification"]:
            pytest.skip(f"{connector_name}: no SCC notification config required")
        configs = list(P.iter_resources(tf_src, "google_scc_notification_config"))
        assert configs, f"{connector_name}: no google_scc_notification_config found"
        _, body = configs[0]
        streaming_body = P.block_body(body, "streaming_config")
        assert streaming_body is not None, (
            f"{connector_name}: scc_notification_config missing streaming_config block"
        )
        assert M.SCC_FILTER_ACTIVE in streaming_body, (
            f"{connector_name}: streaming_config filter does not contain "
            f"{M.SCC_FILTER_ACTIVE!r}; body: {streaming_body!r}"
        )

# ---------------------------------------------------------------------------
# Logging sink filter (audit + vpc)
# ---------------------------------------------------------------------------
class TestLoggingSinkFilter:
    def test_sink_filter_scopes_to_correct_log_type(self, tf_src, connector_name):
        """The logging sink filter must be scoped to the correct log type for
        this connector. An unscoped or wrong filter causes the sink to route
        irrelevant log entries and increases connector processing load."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["has_logging_sink"]:
            pytest.skip(f"{connector_name}: no logging sink")
        sink_tf_name = profile["sink_tf_name"]
        expected_fragment = profile["sink_log_filter_contains"]

        sinks = list(P.iter_resources(tf_src, "google_logging_project_sink"))
        body = next((b for n, b in sinks if n == sink_tf_name), None)
        assert body is not None, (
            f"{connector_name}: logging sink {sink_tf_name!r} not found"
        )
        filter_val = P.scalar(body, "filter")
        assert filter_val is not None, (
            f"{connector_name}: logging sink {sink_tf_name!r} has no filter"
        )
        assert expected_fragment in filter_val, (
            f"{connector_name}: sink filter {filter_val!r} does not contain "
            f"{expected_fragment!r}"
        )

# ---------------------------------------------------------------------------
# Outputs contract
# ---------------------------------------------------------------------------
class TestOutputsContract:
    def test_required_outputs_declared(self, tf_src, connector_name):
        """All required outputs must be declared. Runtime tooling (Helm chart,
        startup scripts) reads these outputs to configure the connector binary --
        a missing output causes a silent misconfiguration at deploy time."""
        declared = P.output_names(tf_src)
        required = M.REQUIRED_OUTPUTS[connector_name]
        missing = required - declared
        assert not missing, (
            f"{connector_name}: outputs.tf is missing: {sorted(missing)}"
        )

    def test_subscription_id_references_correct_subscription(self, tf_src, connector_name):
        """subscription_id output value must reference the correct subscription
        resource's .name attribute."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        sub_tf_name = profile["subscription_tf_name"]
        ref = P.output_ref(tf_src, "subscription_id")
        expected = f"google_pubsub_subscription.{sub_tf_name}.name"
        assert ref == expected, (
            f"{connector_name}: output subscription_id references {ref!r}; "
            f"expected {expected!r}"
        )

    def test_topic_id_references_correct_topic(self, tf_src, connector_name):
        """topic_id output value must reference the correct topic resource's .id."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        topic_tf_name = profile["topic_tf_name"]
        ref = P.output_ref(tf_src, "topic_id")
        expected = f"google_pubsub_topic.{topic_tf_name}.id"
        assert ref == expected, (
            f"{connector_name}: output topic_id references {ref!r}; "
            f"expected {expected!r}"
        )

    def test_sink_writer_references_correct_sink(self, tf_src, connector_name):
        """sink_writer output value must reference the sink's .writer_identity."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["has_logging_sink"]:
            pytest.skip(f"{connector_name}: no logging sink output expected")
        sink_tf_name = profile["sink_tf_name"]
        ref = P.output_ref(tf_src, "sink_writer")
        expected = f"google_logging_project_sink.{sink_tf_name}.writer_identity"
        assert ref == expected, (
            f"{connector_name}: output sink_writer references {ref!r}; "
            f"expected {expected!r}"
        )

# ---------------------------------------------------------------------------
# Parquet egress contract
# ---------------------------------------------------------------------------
class TestServiceAccount:
    def test_connector_sa_exists(self, tf_src, connector_name):
        """Each connector must have a dedicated service account. Sharing the
        default GCE SA or a shared SA gives the connector overly broad GCP
        access and makes the audit trail ambiguous."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        sa_tf_name = profile["connector_sa_tf_name"]
        sas = list(P.iter_resources(tf_src, "google_service_account"))
        body = next((b for n, b in sas if n == sa_tf_name), None)
        assert body is not None, (
            f"{connector_name}: service account {sa_tf_name!r} not found; "
            f"present: {[n for n, _ in sas]}"
        )

    def test_connector_subscriber_iam_exists(self, tf_src, connector_name):
        """The connector SA must have roles/pubsub.subscriber on its
        subscription. Without this binding, every pull call returns
        PERMISSION_DENIED and the connector receives no messages."""
        iam_subs = list(P.iter_resources(tf_src, "google_pubsub_subscription_iam_member"))
        assert iam_subs, (
            f"{connector_name}: no google_pubsub_subscription_iam_member found"
        )
        subscriber_grants = [
            b for _, b in iam_subs
            if P.scalar(b, "role") == "roles/pubsub.subscriber"
        ]
        assert subscriber_grants, (
            f"{connector_name}: no IAM grant for roles/pubsub.subscriber found"
        )

    def test_connector_subscriber_references_connector_sa(self, tf_src, connector_name):
        """The subscriber IAM binding must reference the connector SA provisioned
        in this stack, not a hardcoded service account email that would break
        after SA re-creation."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        sa_tf_name = profile["connector_sa_tf_name"]
        expected_fragment = f"google_service_account.{sa_tf_name}"
        iam_subs = list(P.iter_resources(tf_src, "google_pubsub_subscription_iam_member"))
        subscriber_bodies = [
            b for _, b in iam_subs
            if P.scalar(b, "role") == "roles/pubsub.subscriber"
        ]
        assert any(expected_fragment in b for b in subscriber_bodies), (
            f"{connector_name}: no subscriber IAM binding references "
            f"{expected_fragment!r}"
        )

class TestSecretManagerSecret:
    def test_auth_token_secret_exists(self, tf_src, connector_name):
        """Auth token must be stored in Secret Manager so it can be rotated,
        versioned, and access-controlled independently of the deployment.
        Passing tokens as plain env vars bypasses all of those controls."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        secret_tf_name = profile["secret_tf_name"]
        secrets = list(P.iter_resources(tf_src, "google_secret_manager_secret"))
        body = next((b for n, b in secrets if n == secret_tf_name), None)
        assert body is not None, (
            f"{connector_name}: secret {secret_tf_name!r} not found; "
            f"present: {[n for n, _ in secrets]}"
        )

    def test_secret_uses_auto_replication(self, tf_src, connector_name):
        """auto replication lets GCP choose region placement for HA. Without
        explicit replication config the resource fails validation."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        secret_tf_name = profile["secret_tf_name"]
        secrets = list(P.iter_resources(tf_src, "google_secret_manager_secret"))
        body = next((b for n, b in secrets if n == secret_tf_name), None)
        assert body is not None, f"{connector_name}: secret {secret_tf_name!r} not found"
        assert P.has_block(body, "replication"), (
            f"{connector_name}: secret {secret_tf_name!r} missing replication block"
        )

    def test_secret_accessor_iam_exists(self, tf_src, connector_name):
        """The connector SA must have roles/secretmanager.secretAccessor on the
        auth_token secret. Without this the binary can't fetch its token at
        startup and will fail every gateway request with 401."""
        iam_sms = list(P.iter_resources(tf_src, "google_secret_manager_secret_iam_member"))
        assert iam_sms, (
            f"{connector_name}: no google_secret_manager_secret_iam_member found"
        )
        accessor_grants = [
            b for _, b in iam_sms
            if P.scalar(b, "role") == "roles/secretmanager.secretAccessor"
        ]
        assert accessor_grants, (
            f"{connector_name}: no IAM grant for roles/secretmanager.secretAccessor"
        )

    def test_secret_accessor_references_connector_sa(self, tf_src, connector_name):
        """The secretAccessor IAM binding must reference the connector SA from
        this stack so re-creating the SA automatically revokes and re-grants
        access rather than leaving a dangling binding."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        sa_tf_name = profile["connector_sa_tf_name"]
        expected_fragment = f"google_service_account.{sa_tf_name}"
        iam_sms = list(P.iter_resources(tf_src, "google_secret_manager_secret_iam_member"))
        accessor_bodies = [
            b for _, b in iam_sms
            if P.scalar(b, "role") == "roles/secretmanager.secretAccessor"
        ]
        assert any(expected_fragment in b for b in accessor_bodies), (
            f"{connector_name}: secretAccessor IAM binding does not reference "
            f"{expected_fragment!r}"
        )

class TestDLQDrainSubscription:
    def test_dlq_drain_subscription_exists(self, tf_src, connector_name):
        """vpc: the DLQ topic must have a drain subscription so ops can read and
        replay or discard dead-letter messages. A topic with no subscriptions
        is an unmonitored black hole."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile.get("has_dlq_drain", False):
            pytest.skip(f"{connector_name}: DLQ drain not required")
        drain_tf_name = profile["dlq_drain_subscription_tf_name"]
        subs = list(P.iter_resources(tf_src, "google_pubsub_subscription"))
        body = next((b for n, b in subs if n == drain_tf_name), None)
        assert body is not None, (
            f"{connector_name}: DLQ drain subscription {drain_tf_name!r} not found; "
            f"present: {[n for n, _ in subs]}"
        )

    def test_dlq_drain_references_dlq_topic(self, tf_src, connector_name):
        """The dlq_drain subscription topic must reference the DLQ topic, not
        the main vpc_flows topic. A wrong binding silently drains the main queue
        and starves the connector of flow-log messages."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile.get("has_dlq_drain", False):
            pytest.skip(f"{connector_name}: DLQ drain not required")
        drain_tf_name = profile["dlq_drain_subscription_tf_name"]
        subs = list(P.iter_resources(tf_src, "google_pubsub_subscription"))
        body = next((b for n, b in subs if n == drain_tf_name), None)
        assert body is not None, f"{connector_name}: drain subscription not found"
        ref = P.ref_scalar(body, "topic")
        assert ref is not None and "dlq" in ref, (
            f"{connector_name}: dlq_drain.topic = {ref!r}; "
            f"expected a reference containing 'dlq'"
        )

    def test_dlq_drain_subscriber_iam_exists(self, tf_src, connector_name):
        """The connector SA must have subscriber access on the drain subscription
        so ops can trigger a programmatic drain via the connector during a
        runbook execution without needing individual IAM overrides."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile.get("has_dlq_drain", False):
            pytest.skip(f"{connector_name}: DLQ drain not required")
        drain_tf_name = profile["dlq_drain_subscription_tf_name"]
        iam_subs = list(P.iter_resources(tf_src, "google_pubsub_subscription_iam_member"))
        drain_grants = [
            b for _, b in iam_subs
            if drain_tf_name in b and P.scalar(b, "role") == "roles/pubsub.subscriber"
        ]
        assert drain_grants, (
            f"{connector_name}: no subscriber IAM binding found for "
            f"dlq_drain subscription {drain_tf_name!r}"
        )

    def test_dlq_subscription_id_output_declared(self, tf_src, connector_name):
        """dlq_subscription_id output lets the ops runbook locate the right
        drain subscription without re-reading the Terraform source."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile.get("has_dlq_drain", False):
            pytest.skip(f"{connector_name}: DLQ drain not required")
        assert "dlq_subscription_id" in P.output_names(tf_src), (
            f"{connector_name}: output dlq_subscription_id not declared"
        )

class TestConnectorEgressIsParquet:
    def test_wire_content_type(self):
        """Ensures the logic mirror (which mirrors the Rust transmitter) has the
        correct MIME type. If someone changes this constant, the test forces a
        discussion before it reaches the gateway."""
        _test_dir = os.path.dirname(os.path.abspath(__file__))
        _tier0_dir = os.path.join(os.path.dirname(_test_dir), "tier0")
        if _tier0_dir not in sys.path:
            sys.path.insert(0, _tier0_dir)
        import gcp_connectors_logic_mirror as LM
        assert LM.CONTENT_TYPE == "application/vnd.apache.parquet", (
            f"CONTENT_TYPE = {LM.CONTENT_TYPE!r}; gateway rejects non-parquet batches"
        )

    def test_spool_replay_is_false(self):
        """Pub/Sub pull transport is queue-backed -- SPOOL_REPLAY must be False.
        Setting it True would cause the connector to resend messages on startup,
        producing duplicate telemetry in the gateway."""
        _test_dir = os.path.dirname(os.path.abspath(__file__))
        _tier0_dir = os.path.join(os.path.dirname(_test_dir), "tier0")
        if _tier0_dir not in sys.path:
            sys.path.insert(0, _tier0_dir)
        import gcp_connectors_logic_mirror as LM
        assert LM.SPOOL_REPLAY is False, (
            "SPOOL_REPLAY must be False for queue-backed Pub/Sub transport"
        )
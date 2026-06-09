"""
Tier-2 -- Pub/Sub posture and policy-scanner checks for GCP deploy/ stacks.
"""
import subprocess
import pytest
import iac_deploy_mirror as M
import _iac_parse as P

pytestmark = pytest.mark.tier2

class TestSubscriptionPosture:
    def test_ack_deadline_seconds(self, tf_src, connector_name):
        """ack_deadline_seconds must exceed the connector's batch_timeout_secs (10s)
        so in-flight batches are not redelivered before the connector can ack them.
        60s provides a 6x buffer above the default batch timeout."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        subs = list(P.iter_resources(tf_src, "google_pubsub_subscription"))
        assert subs, f"{connector_name}: no google_pubsub_subscription found"
        sub_name = profile["subscription_tf_name"]
        body = next((b for n, b in subs if n == sub_name), None)
        assert body is not None, (
            f"{connector_name}: subscription {sub_name!r} not found; "
            f"present: {[n for n, _ in subs]}"
        )
        val = P.scalar(body, "ack_deadline_seconds")
        assert val == M.SUBSCRIPTION_POSTURE["ack_deadline_seconds"], (
            f"{connector_name}: {sub_name}.ack_deadline_seconds = {val!r}, "
            f"expected {M.SUBSCRIPTION_POSTURE['ack_deadline_seconds']!r}"
        )

    def test_message_retention_duration(self, tf_src, connector_name):
        """86400s (24h) retention ensures messages survive a full day of gateway
        unavailability without loss -- the connector can always drain on recovery."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        subs = list(P.iter_resources(tf_src, "google_pubsub_subscription"))
        sub_name = profile["subscription_tf_name"]
        body = next((b for n, b in subs if n == sub_name), None)
        assert body is not None, f"{connector_name}: subscription {sub_name!r} not found"
        val = P.scalar(body, "message_retention_duration")
        assert val == M.SUBSCRIPTION_POSTURE["message_retention_duration"], (
            f"{connector_name}: {sub_name}.message_retention_duration = {val!r}, "
            f"expected {M.SUBSCRIPTION_POSTURE['message_retention_duration']!r}"
        )

    def test_retry_policy_exists(self, tf_src, connector_name):
        """retry_policy must be declared so Pub/Sub applies exponential backoff on
        nacked messages. Without it Pub/Sub redelivers immediately and a sustained
        gateway failure produces a tight loop that exhausts CPU and connection
        limits before the gateway recovers."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["required_retry_policy"]:
            pytest.skip(f"{connector_name}: retry_policy not required")
        sub_name = profile["subscription_tf_name"]
        subs = list(P.iter_resources(tf_src, "google_pubsub_subscription"))
        body = next((b for n, b in subs if n == sub_name), None)
        assert body is not None, f"{connector_name}: subscription {sub_name!r} not found"
        assert P.has_block(body, "retry_policy"), (
            f"{connector_name}: {sub_name} is missing a retry_policy block -- "
            f"Pub/Sub will redeliver nacked messages immediately on gateway failure"
        )

    def test_retry_policy_backoff_values(self, tf_src, connector_name):
        """minimum_backoff=10s / maximum_backoff=600s match the connector's own
        batch retry budget. Values that are too low produce storms; too high delay
        recovery. Assert exact values so a future tweak is a conscious decision."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["required_retry_policy"]:
            pytest.skip(f"{connector_name}: retry_policy not required")
        sub_name = profile["subscription_tf_name"]
        subs = list(P.iter_resources(tf_src, "google_pubsub_subscription"))
        body = next((b for n, b in subs if n == sub_name), None)
        assert body is not None, f"{connector_name}: subscription {sub_name!r} not found"
        retry_body = P.block_body(body, "retry_policy")
        if retry_body is None:
            pytest.skip(f"{connector_name}: no retry_policy block -- caught by test_retry_policy_exists")
        for key, expected in M.RETRY_POSTURE.items():
            val = P.scalar(retry_body, key)
            assert val == expected, (
                f"{connector_name}: retry_policy.{key} = {val!r}, expected {expected!r}"
            )

class TestDLQPosture:
    def test_dlq_topic_exists_for_vpc(self, tf_src, connector_name):
        """vpc: a dead-letter topic must exist to absorb permanently unprocessable
        messages and prevent them from blocking the main subscription."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["has_dlq"]:
            pytest.skip(f"{connector_name}: DLQ not applicable")
        topics = list(P.iter_resources(tf_src, "google_pubsub_topic"))
        assert len(topics) >= 2, (
            f"{connector_name}: expected at least 2 google_pubsub_topic resources "
            f"(main + DLQ), found {len(topics)}"
        )

    def test_dead_letter_policy_max_delivery_attempts(self, tf_src, connector_name):
        """max_delivery_attempts=10 limits poison-message loops. Too low (e.g. 5)
        drops valid messages during transient failures; too high (e.g. 1000) makes
        the DLQ effectively useless. 10 matches industry guidance for batch connectors."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile["has_dlq"]:
            pytest.skip(f"{connector_name}: DLQ not applicable")
        sub_name = profile["subscription_tf_name"]
        subs = list(P.iter_resources(tf_src, "google_pubsub_subscription"))
        body = next((b for n, b in subs if n == sub_name), None)
        assert body is not None, f"{connector_name}: subscription {sub_name!r} not found"
        assert P.has_block(body, "dead_letter_policy"), (
            f"{connector_name}: vpc subscription missing dead_letter_policy"
        )
        dlq_body = P.block_body(body, "dead_letter_policy")
        val = P.scalar(dlq_body, "max_delivery_attempts") if dlq_body else None
        assert val == M.DLQ_MAX_DELIVERY_ATTEMPTS, (
            f"{connector_name}: dead_letter_policy.max_delivery_attempts = {val!r}, "
            f"expected {M.DLQ_MAX_DELIVERY_ATTEMPTS!r}"
        )

class TestPolicyScanners:
    def test_checkov_enforces_all_but_documented_na(self, tf_dir, connector_name):
        """checkov passes with no unskipped failures. Every skip must be documented
        in CHECKOV_SKIP with an N/A rationale -- new findings from provider updates
        or config changes fail by default and require a conscious decision to skip."""
        try:
            import subprocess as sp
            skip_flags = []
            for check_id in M.CHECKOV_SKIP:
                skip_flags += ["--skip-check", check_id]
            result = sp.run(
                ["checkov", "-d", tf_dir, "--framework", "terraform",
                 "--quiet", "--compact"] + skip_flags,
                capture_output=True, text=True,
            )
            assert result.returncode == 0, (
                f"{connector_name}: checkov found unskipped policy violations:\n"
                f"{result.stdout[-3000:]}"
            )
        except FileNotFoundError:
            pytest.skip("checkov not installed (present in the tier2 container)")


class TestTerraformVersionPinned:
    def test_required_version_declared(self, tf_src, connector_name):
        """required_version >= 1.9 prevents apply with an older Terraform that
        lacks the provider-schema improvements and input-variable-in-validation
        support these stacks rely on."""
        assert "required_version" in tf_src, (
            f"{connector_name}: terraform block does not declare required_version"
        )

    def test_required_version_is_1_9_or_higher(self, tf_src, connector_name):
        """The pinned version must be at least 1.9. Earlier versions (< 1.9) lack
        stable provider-defined functions and cross-variable validations."""
        import re
        m = re.search(r'required_version\s*=\s*"([^"]+)"', tf_src)
        assert m is not None, f"{connector_name}: required_version not parseable"
        constraint = m.group(1)
        assert "1.9" in constraint or any(
            f"1.{v}" in constraint for v in range(9, 20)
        ), (
            f"{connector_name}: required_version = {constraint!r}; "
            f"expected >= 1.9 (found no 1.9+ version constraint)"
        )


class TestGCSBackend:
    def test_gcs_backend_declared(self, tf_src, connector_name):
        """State must be stored in GCS so the team and CI can share locks and
        outputs. A local backend means each operator has their own state and
        concurrent applies will corrupt it."""
        assert P.has_gcs_backend(tf_src), (
            f"{connector_name}: no backend \"gcs\" block found in the terraform block"
        )


class TestLabelsVariable:
    def test_labels_variable_declared(self, tf_src, connector_name):
        """A labels variable lets operators attach org-wide cost-allocation and
        incident-triage tags at deploy time without editing the Terraform source."""
        assert P.has_variable(tf_src, "labels"), (
            f"{connector_name}: variable \"labels\" not declared"
        )

    def test_alert_notification_channels_variable_declared(self, tf_src, connector_name):
        """alert_notification_channels lets ops wire queue-age alerts to
        PagerDuty, Slack, or email channels at deploy time."""
        assert P.has_variable(tf_src, "alert_notification_channels"), (
            f"{connector_name}: variable \"alert_notification_channels\" not declared"
        )


class TestMonitoringAlerts:
    def test_queue_age_alert_exists(self, tf_src, connector_name):
        """A queue-age alert catches connector or gateway downtime before
        messages expire. Without it a silent outage goes undetected until
        customers report missing data."""
        alerts = list(P.iter_resources(tf_src, "google_monitoring_alert_policy"))
        assert alerts, f"{connector_name}: no google_monitoring_alert_policy found"

    def test_queue_age_alert_filter_references_subscription(self, tf_src, connector_name):
        """The alert filter must reference the subscription via a Terraform
        resource reference so it tracks the subscription through renames."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        sub_tf_name = profile["subscription_tf_name"]
        expected_fragment = f"google_pubsub_subscription.{sub_tf_name}"
        alert_tf_name = profile["alert_tf_name"]
        alerts = list(P.iter_resources(tf_src, "google_monitoring_alert_policy"))
        body = next((b for n, b in alerts if n == alert_tf_name), None)
        assert body is not None, (
            f"{connector_name}: alert policy {alert_tf_name!r} not found; "
            f"present: {[n for n, _ in alerts]}"
        )
        assert expected_fragment in body, (
            f"{connector_name}: alert filter does not reference {expected_fragment!r}"
        )


class TestDLQMonitoringAlert:
    def test_dlq_alert_exists_for_vpc(self, tf_src, connector_name):
        """vpc: a DLQ alert fires immediately when dead-letter messages
        accumulate. Without it a burst of poison messages fills the DLQ
        silently and ops has no signal to investigate."""
        profile = M.CONNECTOR_PROFILE[connector_name]
        if not profile.get("has_dlq_drain", False):
            pytest.skip(f"{connector_name}: DLQ drain not required")
        dlq_alert_name = profile["dlq_alert_tf_name"]
        alerts = list(P.iter_resources(tf_src, "google_monitoring_alert_policy"))
        body = next((b for n, b in alerts if n == dlq_alert_name), None)
        assert body is not None, (
            f"{connector_name}: DLQ alert policy {dlq_alert_name!r} not found; "
            f"present: {[n for n, _ in alerts]}"
        )
"""
Lab 11: Operations Contracts -- containment.toml + NATS streams_init.sh

Validates:
  - containment.toml TOML validity and provider structure
  - Cloud routing source_type → provider mapping completeness
  - EDR/firewall/SSH fallback action definitions
  - streams_init.sh creates all 9 required NATS streams
  - Stream subjects match what workers publish/subscribe to
  - Quorum replica count (3, never even)

All offline -- reads source files, no services required.
"""
import re
import tomllib
from pathlib import Path

CONTAINMENT_TOML = Path(__file__).parent.parent.parent / "operations/infra/containment.toml"
STREAMS_SH = Path(__file__).parent.parent.parent / "infrastructure/nats/streams_init.sh"


def _toml():
    return tomllib.loads(CONTAINMENT_TOML.read_text())


def _sh():
    return STREAMS_SH.read_text()


# ── containment.toml ──────────────────────────────────────────────────────────

class TestContainmentTOMLValidity:
    """File-level validity."""

    def test_valid_toml_syntax(self):
        data = _toml()
        assert isinstance(data, dict)

    def test_top_level_keys_present(self):
        data = _toml()
        for key in ("global", "cloud_routing", "providers"):
            assert key in data, f"[{key}] section must be present"


class TestContainmentGlobal:
    """[global] section contracts."""

    def test_default_callback_timeout_defined(self):
        assert "default_callback_timeout" in _toml()["global"]

    def test_retry_max_attempts_defined(self):
        assert "retry_max_attempts" in _toml()["global"]

    def test_active_edr_defined(self):
        assert "active_edr" in _toml()["global"]

    def test_active_firewall_defined(self):
        assert "active_firewall" in _toml()["global"]

    def test_active_playbook_executor_defined(self):
        assert "active_playbook_executor" in _toml()["global"], \
            "[global] must define active_playbook_executor for EDR-less fallback"


class TestCloudRouting:
    """[cloud_routing] maps source_types to cloud providers."""

    def test_aws_source_types_complete(self):
        cr = _toml()["cloud_routing"]
        aws = cr["aws_source_types"]
        for st in ("aws_guardduty", "aws_cloudtrail", "aws_vpc"):
            assert st in aws, f"{st} must be in aws_source_types"

    def test_azure_source_types_complete(self):
        cr = _toml()["cloud_routing"]
        azure = cr["azure_source_types"]
        for st in ("azure_entraid", "azure_activity", "azure_nsg"):
            assert st in azure, f"{st} must be in azure_source_types"

    def test_gcp_source_types_complete(self):
        cr = _toml()["cloud_routing"]
        gcp = cr["gcp_source_types"]
        for st in ("gcp_audit", "gcp_scc", "gcp_vpc_flow"):
            assert st in gcp, f"{st} must be in gcp_source_types"

    def test_vmware_source_types_present(self):
        cr = _toml()["cloud_routing"]
        assert "vmware_syslog" in cr["vmware_source_types"]

    def test_cloud_containment_webhook_is_n8n(self):
        webhook = _toml()["cloud_routing"].get("cloud_containment_webhook", "")
        assert "n8n" in webhook, "Cloud containment must route through n8n"

    def test_cloud_source_types_align_with_unified_alert_schema(self):
        """Source types in containment.toml must be a subset of valid UnifiedAlertSchema source_types."""
        valid_source_types = {
            "aws_vpc", "aws_cloudtrail", "aws_guardduty",
            "azure_nsg", "azure_activity", "azure_entraid",
            "gcp_audit", "gcp_scc", "gcp_vpc_flow",
            "vmware_syslog",
        }
        cr = _toml()["cloud_routing"]
        all_cloud_types = (
            cr["aws_source_types"] +
            cr["azure_source_types"] +
            cr["gcp_source_types"] +
            cr["vmware_source_types"]
        )
        for st in all_cloud_types:
            assert st in valid_source_types, \
                f"{st} in containment.toml is not a recognized UnifiedAlertSchema source_type"


class TestEDRProvider:
    """custom_edr_v1 provider must support host isolation lifecycle."""

    def _edr(self):
        return _toml()["providers"]["custom_edr_v1"]

    def test_isolate_host_action_exists(self):
        assert "isolate_host" in self._edr()["actions"]

    def test_release_host_action_exists(self):
        assert "release_host" in self._edr()["actions"]

    def test_isolate_uses_post_method(self):
        assert self._edr()["actions"]["isolate_host"]["method"] == "POST"

    def test_isolate_is_retryable(self):
        assert self._edr()["actions"]["isolate_host"]["retryable"] is True

    def test_release_requires_incident_id(self):
        required = self._edr()["actions"]["release_host"]["validation"]["required_fields"]
        assert "incident_id" in required


class TestFirewallProvider:
    """custom_fw_v1 provider must support bidirectional IP blocking."""

    def _fw(self):
        return _toml()["providers"]["custom_fw_v1"]

    def test_block_ip_action_exists(self):
        assert "block_ip" in self._fw()["actions"]

    def test_unblock_ip_action_exists(self):
        assert "unblock_ip" in self._fw()["actions"]

    def test_block_ip_requires_target_and_incident_id(self):
        required = self._fw()["actions"]["block_ip"]["validation"]["required_fields"]
        assert "target" in required and "incident_id" in required


class TestSSHFallbackProvider:
    """ssh_playbook_v1: routes to n8n when no EDR agent is present on endpoint."""

    def _ssh(self):
        return _toml()["providers"]["ssh_playbook_v1"]

    def test_isolate_host_routes_to_n8n(self):
        endpoint = self._ssh()["actions"]["isolate_host"]["endpoint"]
        assert "n8n" in endpoint

    def test_block_ip_routes_to_n8n(self):
        endpoint = self._ssh()["actions"]["block_ip"]["endpoint"]
        assert "n8n" in endpoint

    def test_fallback_webhook_path(self):
        endpoint = self._ssh()["actions"]["isolate_host"]["endpoint"]
        assert "fallback-containment" in endpoint


class TestAWSProvider:
    """aws_containment_v1: Lambda Function URLs for EC2 isolation."""

    def _aws(self):
        return _toml()["providers"]["aws_containment_v1"]

    def test_all_four_actions_defined(self):
        actions = self._aws()["actions"]
        for a in ("isolate_host", "release_host", "block_ip", "unblock_ip"):
            assert a in actions, f"AWS provider must define {a}"

    def test_uses_nexus_hmac_signature(self):
        headers = self._aws()["actions"]["isolate_host"]["headers"]
        assert any("NEXUS_HMAC_SECRET" in str(v) for v in headers.values()), \
            "AWS provider must use NEXUS_HMAC_SECRET for request signing"


# ── streams_init.sh ───────────────────────────────────────────────────────────

class TestStreamsInitScript:
    """streams_init.sh creates the 9 required NATS JetStream streams."""

    REQUIRED_STREAMS = [
        "MiddlewareStream",
        "MiddlewareStream_DLQ",
        "Tier5_Telemetry",
        "Nexus_Math_Alerts",
        "Nexus_Baseline_Alerts",
        "Nexus_SOAR_Execute",
        "Nexus_SOAR_Callback",
        "Nexus_RLHF_Training",
        "Nexus_DLQ",
    ]

    def test_all_9_streams_defined(self):
        sh = _sh()
        for stream in self.REQUIRED_STREAMS:
            assert stream in sh, f"Stream '{stream}' must be created in streams_init.sh"

    def test_tier5_telemetry_wildcard_subject(self):
        assert "nexus.*.telemetry" in _sh(), \
            "Tier5_Telemetry must subscribe to nexus.*.telemetry (wildcard for all sensor types)"

    def test_soar_execute_subject(self):
        assert "nexus.soar.execute" in _sh(), \
            "Nexus_SOAR_Execute stream must match nexus.soar.execute subject"

    def test_soar_callback_subject(self):
        assert "nexus.soar.callback" in _sh()

    def test_math_alerts_subject(self):
        assert "nexus.alerts.math" in _sh()

    def test_baseline_alerts_subject(self):
        assert "nexus.alerts.baseline" in _sh()

    def test_rlhf_subject(self):
        assert "nexus.training.rlhf.records" in _sh()

    def test_dlq_wildcard_subject(self):
        assert "nexus.dlq.>" in _sh()

    def test_middleware_subject(self):
        assert "middleware.telemetry.*" in _sh()

    def test_3_replicas_used(self):
        sh = _sh()
        # Every create_stream invocation must pass 3 as replica count
        # Regex: find the 5th arg (replicas) of each create_stream call
        calls = re.findall(
            r'create_stream\s*\\\s*\n\s*"[^"]+"\s*\\\s*\n\s*"[^"]+"\s*\\\s*\n\s*\d+\s*\\\s*\n\s*(-?\d+)\s*\\\s*\n\s*(\d+)',
            sh,
        )
        for max_bytes, replicas in calls:
            assert replicas == "3", f"Stream must use 3 replicas (quorum), found {replicas}"

    def test_set_e_error_propagation(self):
        assert "set -e" in _sh(), "Script must use set -e to propagate stream creation errors"

    def test_bash_shebang(self):
        assert _sh().startswith("#!/bin/bash"), "streams_init.sh must have bash shebang"

    def test_health_check_before_stream_creation(self):
        sh = _sh()
        assert "healthz" in sh, \
            "Script must poll NATS /healthz before attempting stream creation"

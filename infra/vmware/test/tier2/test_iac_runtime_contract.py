"""
Tier2 — IaC runtime contract: exporter wiring, outputs, Parquet egress.
"""
import re
import pytest

from _iac_parse import (
    has_resource,
    resource_body,
    output_value,
    has_variable,
    attr_value,
    provider_body,
)
from iac_deploy_mirror import (
    NSXT_EXPORTER_RESOURCE_TYPE,
    NSXT_EXPORTER_RESOURCE_NAME,
    REQUIRED_OUTPUTS,
)

class TestNSXTExporterWiring:
    """
    The vmware/nsxt provider has no first-class resource for node syslog.
    We use a null_resource + local-exec provisioner calling the NSX-T REST API.
    Tests check that the provisioner references the right variables.
    """

    def test_exporter_resource_declared(self, tf_src):
        assert has_resource(
            tf_src,
            NSXT_EXPORTER_RESOURCE_TYPE,
            NSXT_EXPORTER_RESOURCE_NAME,
        ), (
            f"Resource {NSXT_EXPORTER_RESOURCE_TYPE!r} "
            f"{NSXT_EXPORTER_RESOURCE_NAME!r} not declared"
        )

    def test_exporter_references_collector_host(self, tf_src):
        """The syslog exporter must reference var.collector_host."""
        body = resource_body(tf_src, NSXT_EXPORTER_RESOURCE_TYPE, NSXT_EXPORTER_RESOURCE_NAME)
        assert body is not None, "nsxt_syslog_exporter resource block not found"
        assert "var.collector_host" in body, \
            "nsxt_syslog_exporter must reference var.collector_host"

    def test_exporter_references_collector_port(self, tf_src):
        body = resource_body(tf_src, NSXT_EXPORTER_RESOURCE_TYPE, NSXT_EXPORTER_RESOURCE_NAME)
        assert body is not None
        assert "var.collector_port" in body, \
            "nsxt_syslog_exporter must reference var.collector_port"

    def test_exporter_references_collector_protocol(self, tf_src):
        body = resource_body(tf_src, NSXT_EXPORTER_RESOURCE_TYPE, NSXT_EXPORTER_RESOURCE_NAME)
        assert body is not None
        assert "var.collector_protocol" in body, \
            "nsxt_syslog_exporter must reference var.collector_protocol"

    def test_exporter_debug_log_level(self, tf_src):
        """The provisioner command must request DEBUG log level for DFW telemetry."""
        body = resource_body(tf_src, NSXT_EXPORTER_RESOURCE_TYPE, NSXT_EXPORTER_RESOURCE_NAME)
        assert body is not None
        assert "DEBUG" in body, \
            "Provisioner must request DEBUG log level for DFW packet-level telemetry"

    def test_exporter_uses_nsxt_credentials(self, tf_src):
        """Provisioner must reference nsxt_username/nsxt_password or env vars."""
        body = resource_body(tf_src, NSXT_EXPORTER_RESOURCE_TYPE, NSXT_EXPORTER_RESOURCE_NAME)
        assert body is not None
        assert "nsxt_username" in body or "NSXT_USER" in body, \
            "Provisioner must use NSX-T credentials"

    def test_exporter_targets_nsxt_api(self, tf_src):
        """Provisioner must target the NSX-T syslog exporters API endpoint."""
        body = resource_body(tf_src, NSXT_EXPORTER_RESOURCE_TYPE, NSXT_EXPORTER_RESOURCE_NAME)
        assert body is not None
        assert "syslog" in body.lower(), \
            "Provisioner must target the NSX-T syslog API endpoint"

class TestOutputsContract:
    @pytest.mark.parametrize("output_name", REQUIRED_OUTPUTS)
    def test_output_declared(self, tf_src, output_name):
        val = output_value(tf_src, output_name)
        assert val is not None, \
            f"Required output '{output_name}' not declared in outputs.tf"

    def test_collector_endpoint_uses_variables(self, tf_src):
        val = output_value(tf_src, "collector_endpoint")
        assert val is not None, "collector_endpoint output missing"
        assert "var.collector_protocol" in val or "collector_protocol" in val
        assert "var.collector_host" in val or "collector_host" in val
        assert "var.collector_port" in val or "collector_port" in val

    def test_nsxt_exporter_output_references_resource(self, tf_src):
        val = output_value(tf_src, "nsxt_exporter")
        assert val is not None, "nsxt_exporter output missing"
        assert "nsxt_syslog_exporter" in val or "null_resource" in val, \
            "nsxt_exporter output should reference the null_resource.nsxt_syslog_exporter"

class TestConnectorEgressIsParquet:
    """Verify Rust source commits to Parquet content type on egress."""

    def test_content_type_header(self, src_dir):
        import os
        with open(os.path.join(src_dir, "transmitter.rs")) as f:
            src = f.read()
        assert "application/vnd.apache.parquet" in src, \
            "transmitter.rs must set Content-Type: application/vnd.apache.parquet"

    def test_parquet_write_used(self, src_dir):
        import os
        with open(os.path.join(src_dir, "transmitter.rs")) as f:
            src = f.read()
        assert "ArrowWriter" in src or "parquet" in src.lower(), \
            "transmitter.rs must use the Parquet writer (ArrowWriter)"

class TestProviderAuthentication:
    def test_nsxt_uses_username_variable(self, tf_src):
        body = provider_body(tf_src, "nsxt")
        assert body, "nsxt provider block not found"
        assert "var.nsxt_username" in body

    def test_nsxt_uses_password_variable(self, tf_src):
        body = provider_body(tf_src, "nsxt")
        assert body
        assert "var.nsxt_password" in body

    def test_vsphere_uses_user_variable(self, tf_src):
        body = provider_body(tf_src, "vsphere")
        assert body, "vsphere provider block not found"
        assert "var.vsphere_user" in body

    def test_vsphere_uses_password_variable(self, tf_src):
        body = provider_body(tf_src, "vsphere")
        assert body
        assert "var.vsphere_password" in body

class TestRuntimeEnvDocumentation:
    """Connector runtime env vars must be documented in main.tf."""

    REQUIRED_ENV_VARS = [
        "AUTH_TOKEN",
        "GATEWAY_URL",
        "INTEGRITY_SECRET",
        "SENSOR_ID",
        "SYSLOG_BIND",
    ]

    def test_env_vars_documented(self, tf_src):
        missing = [v for v in self.REQUIRED_ENV_VARS if v not in tf_src]
        assert not missing, (
            f"Runtime env vars not documented in main.tf: {missing}"
        )
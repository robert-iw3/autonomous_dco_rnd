"""
Tier2 — IaC posture: provider versions, sensitive vars, SSL, log levels, checkov.
"""
import json
import os
import re
import subprocess
import pytest

from _iac_parse import (
    provider_body,
    variable_body,
    required_provider_version,
    has_variable,
    has_explicit_backend,
    attr_value,
)
from iac_deploy_mirror import (
    REQUIRED_PROVIDERS,
    REQUIRED_TF_VERSION_CONSTRAINT,
    BACKEND_TYPE,
    REQUIRED_LOG_LEVELS,
    REQUIRED_VARIABLES,
    SENSITIVE_VARIABLES,
    CHECKOV_SKIP,
)

class TestProviderVersionPinned:
    @pytest.mark.parametrize("source,expected", list(REQUIRED_PROVIDERS.items()))
    def test_provider_version(self, tf_src, source, expected):
        got = required_provider_version(tf_src, source)
        assert got is not None, f"Provider '{source}' not found in required_providers"
        assert got == expected, (
            f"Provider '{source}' version: expected {expected!r}, got {got!r}"
        )

class TestTerraformVersionPinned:
    def test_required_version_present(self, tf_src):
        assert REQUIRED_TF_VERSION_CONSTRAINT in tf_src, (
            f"required_version constraint {REQUIRED_TF_VERSION_CONSTRAINT!r} "
            "not found in Terraform config"
        )

class TestSSLEnforcement:
    def test_nsxt_ssl_not_disabled(self, tf_src):
        body = provider_body(tf_src, "nsxt")
        assert body is not None, "nsxt provider block not found"
        m = re.search(r'allow_unverified_ssl\s*=\s*(\w+)', body)
        assert m is not None, "allow_unverified_ssl not set in nsxt provider"
        assert m.group(1) == "false", \
            "nsxt provider must have allow_unverified_ssl = false"

    def test_vsphere_ssl_not_disabled(self, tf_src):
        body = provider_body(tf_src, "vsphere")
        assert body is not None, "vsphere provider block not found"
        m = re.search(r'allow_unverified_ssl\s*=\s*(\w+)', body)
        assert m is not None, "allow_unverified_ssl not set in vsphere provider"
        assert m.group(1) == "false", \
            "vsphere provider must have allow_unverified_ssl = false"

class TestSensitiveVariables:
    @pytest.mark.parametrize("varname", SENSITIVE_VARIABLES)
    def test_variable_is_sensitive(self, tf_src, varname):
        body = variable_body(tf_src, varname)
        assert body is not None, f"Variable '{varname}' not declared"
        assert "sensitive" in body and "true" in body, \
            f"Variable '{varname}' must have sensitive = true"

class TestRequiredVariables:
    @pytest.mark.parametrize("varname", REQUIRED_VARIABLES)
    def test_variable_declared(self, tf_src, varname):
        assert has_variable(tf_src, varname), \
            f"Required variable '{varname}' not declared"

class TestLogLevels:
    def test_debug_log_level_present(self, tf_src):
        """NSX-T syslog configuration must use DEBUG log level for DFW packet telemetry.

        The vmware/nsxt provider does not expose a first-class resource for node
        syslog; the log_level is set in the REST API provisioner command instead.
        """
        assert '"DEBUG"' in tf_src or "'DEBUG'" in tf_src or "DEBUG" in tf_src, (
            "DEBUG log level not found in Terraform config. "
            "Required for DFW packet-level telemetry."
        )

class TestExplicitBackend:
    def test_local_backend_declared(self, tf_src):
        assert has_explicit_backend(tf_src, "local"), (
            "No explicit 'backend \"local\" {}' found. "
            "On-premises VMware deployments must explicitly declare the backend."
        )

class TestCheckov:
    def test_checkov_passes(self, tf_dir, _plugin_cache):
        """Checkov security scan must pass with no HIGH/CRITICAL findings."""
        skip_args = []
        for check_id in CHECKOV_SKIP:
            skip_args += ["--skip-check", check_id]

        r = subprocess.run(
            [
                "checkov",
                "--directory", tf_dir,
                "--framework", "terraform",
                "--output", "json",
                "--compact",
                "--quiet",
            ] + skip_args,
            capture_output=True,
            text=True,
        )

        # checkov exits 1 on failures, but we parse JSON to get details.
        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            pytest.fail(f"checkov output was not valid JSON:\n{r.stdout}\n{r.stderr}")

        results = data if isinstance(data, list) else [data]
        failed = []
        for result in results:
            for check in result.get("results", {}).get("failed_checks", []):
                sev = check.get("check_result", {}).get("result", "")
                check_id = check.get("check_id", "")
                if check_id not in CHECKOV_SKIP:
                    failed.append(f"{check_id}: {check.get('check', {}).get('name', '')}")

        assert not failed, (
            f"Checkov found {len(failed)} failing check(s):\n" + "\n".join(failed)
        )
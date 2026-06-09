"""
Expected IaC constants for the VMware NSX-T/vSphere stack.

Used by tier2 tests to verify the Terraform source matches the
production-ready deployment spec without hard-coding values in
every test.
"""

# ---------------------------------------------------------------------------
# Provider requirements
# ---------------------------------------------------------------------------
REQUIRED_PROVIDERS = {
    "vmware/nsxt":    "~> 3.4",
    "vmware/vsphere": "~> 2.6",
    "hashicorp/null": "~> 3.0",
}

REQUIRED_TF_VERSION_CONSTRAINT = ">= 1.9"

# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------
BACKEND_TYPE = "local"

# ---------------------------------------------------------------------------
# NSX-T exporter resource
# ---------------------------------------------------------------------------
NSXT_EXPORTER_RESOURCE_TYPE = "null_resource"
NSXT_EXPORTER_RESOURCE_NAME = "nsxt_syslog_exporter"

# The log_levels list must include at least these four to capture DFW
# packet-level telemetry (DEBUG) plus management-plane events.
REQUIRED_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}

# ---------------------------------------------------------------------------
# Variables that must exist
# ---------------------------------------------------------------------------
REQUIRED_VARIABLES = [
    "environment",
    "project_name",
    "collector_host",
    "collector_port",
    "collector_protocol",
    "nsxt_manager_host",
    "nsxt_username",
    "nsxt_password",
    "vsphere_server",
    "vsphere_user",
    "vsphere_password",
]

SENSITIVE_VARIABLES = [
    "nsxt_username",
    "nsxt_password",
    "vsphere_user",
    "vsphere_password",
]

# ---------------------------------------------------------------------------
# Outputs contract
# ---------------------------------------------------------------------------
REQUIRED_OUTPUTS = [
    "collector_endpoint",
    "nsxt_exporter",
]

# ---------------------------------------------------------------------------
# SSL enforcement
# These provider attributes must be false (SSL verification enabled).
# ---------------------------------------------------------------------------
SSL_ALLOW_UNVERIFIED_ATTRS = {
    "nsxt":    ("provider_nsxt",    "allow_unverified_ssl"),
    "vsphere": ("provider_vsphere", "allow_unverified_ssl"),
}

# ---------------------------------------------------------------------------
# Checkov skip list — skips that are intentional and must be documented
# On-premises VMware deployment; no cloud-managed CMEK applies.
# ---------------------------------------------------------------------------
CHECKOV_SKIP: list[str] = []
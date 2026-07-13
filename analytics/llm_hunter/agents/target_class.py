"""
Target-class and environment resolver.

Pure / stdlib-only (like playbook_planner / lateral_movement) so the containment
planner is exercised deterministically. Maps an alert source and a single
confirmed-TP entity onto the (target_class, environment) pair the containment
capability contract is keyed by, so a domain, a user, a cloud instance and a host
each get a tailored action instead of a blunt host isolate. Unknown entity types
resolve to ("unknown", ...) so the coverage gate escalates them to an operator
rather than dropping them.

Source lists mirror operations/infra/containment.toml cloud_routing and
playbook_planner's OS map; a drift test keeps them reconciled.
"""
from __future__ import annotations

from agents.lateral_movement import is_internal_ip

TARGET_CLASSES = frozenset({
    "endpoint", "cloud_instance", "container", "identity",
    "network", "saas", "datastore", "unknown",
})

# source_type -> endpoint OS (mirrors playbook_planner windows/linux sources).
_ENDPOINT_OS = {
    "sysmon_sensor": "windows", "windows_deepsensor": "windows",
    "windows_c2": "windows", "trellix_ens": "windows",
    "linux_sentinel": "linux", "linux_c2": "linux",
}
# source_type -> cloud provider (mirrors containment.toml cloud_routing).
_CLOUD_PROVIDER = {
    "aws_guardduty": "aws", "aws_cloudtrail": "aws", "aws_vpc": "aws",
    "azure_entraid": "azure", "azure_activity": "azure", "azure_nsg": "azure",
    "gcp_audit": "gcp", "gcp_scc": "gcp", "gcp_vpc_flow": "gcp",
    "vmware_syslog": "vmware",
}
_CLOUD = frozenset({"aws", "azure", "gcp", "vmware"})

# Host-local artifacts: not standalone targets; carried as endpoint eradication
# params, so they resolve to the endpoint they live on.
_HOST_ARTIFACTS = frozenset({"pid", "hash", "file", "process"})
_IDENTITY_TYPES = frozenset({
    "user", "access_key", "token", "credential", "api_key", "secret", "service_account",
})
_INSTANCE_TYPES = frozenset({"instance", "instance_id", "resource_id", "arn", "vm"})
_DATASTORE_TYPES = frozenset({"bucket", "blob", "storage", "datastore"})


def source_environment(source_type: str) -> str:
    """Deployment environment the alert came from: an endpoint OS (windows/linux)
    or a cloud provider (aws/azure/gcp/vmware), or '' if generic."""
    st = str(source_type or "").strip().lower()
    return _ENDPOINT_OS.get(st) or _CLOUD_PROVIDER.get(st) or ""


def idp_for(env: str) -> str:
    """Identity provider that owns credentials in this environment."""
    return {"aws": "iam", "azure": "entra", "gcp": "gcp"}.get(env, "local")


def net_env(env: str) -> str:
    """Where a network block lands: the cloud SG/firewall, else the on-prem fabric."""
    return env if env in _CLOUD else "onprem"


def classify_entity(entity_id: str, entity_data: dict, source_env: str) -> tuple:
    """One malicious entity -> (target_class, environment) for capability lookup."""
    etype = str((entity_data or {}).get("type", "")).strip().lower()
    eid = str(entity_id)

    if etype in _IDENTITY_TYPES:
        return ("identity", idp_for(source_env))
    if etype in ("domain", "url"):
        return ("network", net_env(source_env))
    if etype in ("container", "pod"):
        return ("container", "k8s")
    if etype in _INSTANCE_TYPES:
        return ("cloud_instance", source_env)
    if etype in _DATASTORE_TYPES:
        return ("datastore", source_env)
    if etype == "ip":
        if is_internal_ip(eid):
            return ("cloud_instance", source_env) if source_env in _CLOUD \
                else ("endpoint", source_env)
        return ("network", net_env(source_env))
    if etype in _HOST_ARTIFACTS:
        return ("endpoint", source_env)
    return ("unknown", source_env)

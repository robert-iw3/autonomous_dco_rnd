"""
nexus-gcp-isolate -- Cloud Function
Creates or deletes a VPC firewall deny rule for a target IP.
Called by n8n Cloud_Containment workflow or worker_soar.

HTTP POST payload:
  {
    "incident_id": "INC-XXXX",
    "target_ip":   "1.2.3.4",
    "action":      "isolate" | "release" | "snapshot_volume",
    "network":     "default"   # optional override
  }

Requires: roles/compute.securityAdmin on the project (firewall rules) and
roles/compute.storageAdmin (disk snapshots).
"""

import json
import os
import hashlib
import hmac
import functions_framework
from googleapiclient import discovery
from google.auth import default

PROJECT_ID   = os.environ.get("GCP_PROJECT", "")
NETWORK      = os.environ.get("GCP_NETWORK", "default")
HMAC_SECRET  = os.environ.get("NEXUS_HMAC_SECRET", "").encode()
RULE_PREFIX  = "nexus-deny"
PRIORITY     = 900  # high priority -- overrides allow rules


def get_service():
    creds, project = default()
    return discovery.build("compute", "v1", credentials=creds), project or PROJECT_ID


def rule_name(target_ip: str, incident_id: str) -> str:
    safe_ip = target_ip.replace(".", "-")
    safe_inc = incident_id.lower().replace("_", "-").replace("/", "-")[:20]
    return f"{RULE_PREFIX}-{safe_ip}-{safe_inc}"


def isolate_ip(service, project: str, target_ip: str, incident_id: str, network: str) -> dict:
    name = rule_name(target_ip, incident_id)
    body = {
        "name": name,
        "description": f"Nexus auto-isolation: {incident_id}",
        "network": f"global/networks/{network}",
        "priority": PRIORITY,
        "direction": "INGRESS",
        "denied": [{"IPProtocol": "all"}],
        "sourceRanges": [f"{target_ip}/32"],
        "targetTags": [],
    }
    op = service.firewalls().insert(project=project, body=body).execute()

    # Also create egress deny rule
    egress_name = f"{name}-egress"
    egress_body = {
        "name": egress_name,
        "description": f"Nexus auto-isolation egress: {incident_id}",
        "network": f"global/networks/{network}",
        "priority": PRIORITY,
        "direction": "EGRESS",
        "denied": [{"IPProtocol": "all"}],
        "destinationRanges": [f"{target_ip}/32"],
    }
    service.firewalls().insert(project=project, body=egress_body).execute()

    return {
        "status":     "CONTAINED",
        "ingress_rule": name,
        "egress_rule":  egress_name,
        "operation":   op.get("name"),
    }


def release_ip(service, project: str, target_ip: str, incident_id: str) -> dict:
    name = rule_name(target_ip, incident_id)
    deleted = []
    for rule in [name, f"{name}-egress"]:
        try:
            service.firewalls().delete(project=project, firewall=rule).execute()
            deleted.append(rule)
        except Exception:
            pass
    return {"status": "RELEASED", "deleted_rules": deleted}


def _find_instance(service, project: str, target_ip: str):
    """Resolve (instance, zone) by internal or NAT IP across all zones."""
    agg = service.instances().aggregatedList(project=project).execute()
    for scope, payload in (agg.get("items") or {}).items():
        for inst in payload.get("instances", []) or []:
            for nic in inst.get("networkInterfaces", []) or []:
                nat_ips = [ac.get("natIP") for ac in nic.get("accessConfigs", []) or []]
                if nic.get("networkIP") == target_ip or target_ip in nat_ips:
                    zone = inst["zone"].rsplit("/", 1)[-1]
                    return inst, zone
    return None, None


def _snapshot_name(incident_id: str, disk_name: str) -> str:
    """RFC1035 snapshot name: lowercase, hyphens, <=62 chars."""
    safe_inc = "".join(c if c.isalnum() else "-" for c in incident_id.lower())[:20]
    return f"nexus-{safe_inc}-{disk_name}"[:62].rstrip("-")


def snapshot_volume(service, project: str, target_ip: str, incident_id: str) -> dict:
    """Evidence-first: snapshot every disk attached to the target instance."""
    inst, zone = _find_instance(service, project, target_ip)
    if not inst:
        raise RuntimeError(f"no instance found for ip={target_ip}")
    snapshots = []
    for disk in inst.get("disks", []) or []:
        disk_name = (disk.get("source") or "").rsplit("/", 1)[-1]
        if not disk_name:
            continue
        body = {
            "name": _snapshot_name(incident_id, disk_name),
            "description": f"Nexus IR evidence snapshot {incident_id} ({inst['name']})",
            "labels": {"nexus-managed": "true", "nexus-component": "containment"},
        }
        service.disks().createSnapshot(
            project=project, zone=zone, disk=disk_name, body=body).execute()
        snapshots.append(body["name"])
    if not snapshots:
        raise RuntimeError(f"no disks attached to instance {inst['name']}")
    return {"status": "SNAPSHOTTED", "instance": inst["name"], "zone": zone,
            "snapshots": snapshots}


@functions_framework.http
def isolate(request):
    # Validate HMAC if secret is configured
    if HMAC_SECRET:
        sig_header = request.headers.get("X-Nexus-Signature", "")
        body = request.get_data()
        expected = hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig_header, expected):
            return json.dumps({"error": "invalid signature"}), 403, {"Content-Type": "application/json"}

    data = request.get_json(force=True, silent=True) or {}

    incident_id = data.get("incident_id", "UNKNOWN")
    target_ip   = data.get("target_ip", "")
    action      = data.get("action", "isolate")
    network     = data.get("network") or NETWORK

    if not target_ip:
        return json.dumps({"error": "target_ip required"}), 400, {"Content-Type": "application/json"}

    try:
        service, project = get_service()

        if action == "isolate":
            result = isolate_ip(service, project, target_ip, incident_id, network)
        elif action == "release":
            result = release_ip(service, project, target_ip, incident_id)
        elif action == "snapshot_volume":
            result = snapshot_volume(service, project, target_ip, incident_id)
        else:
            return json.dumps({"error": f"unknown action: {action}"}), 400, {"Content-Type": "application/json"}

        result["incident_id"] = incident_id
        result["target_ip"]   = target_ip
        return json.dumps(result), 200, {"Content-Type": "application/json"}

    except Exception as e:
        body = json.dumps({"incident_id": incident_id, "status": "FAILED", "detail": str(e)})
        return body, 500, {"Content-Type": "application/json"}

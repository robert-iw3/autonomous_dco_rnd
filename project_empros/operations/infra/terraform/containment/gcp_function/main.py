"""
nexus-gcp-isolate -- Cloud Function
Creates or deletes a VPC firewall deny rule for a target IP.
Called by n8n Cloud_Containment workflow or worker_soar.

HTTP POST payload:
  {
    "incident_id": "INC-XXXX",
    "target_ip":   "1.2.3.4",
    "action":      "isolate" | "release",
    "network":     "default"   # optional override
  }

Requires: roles/compute.securityAdmin on the project.
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


def isolate(service, project: str, target_ip: str, incident_id: str, network: str) -> dict:
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


def release(service, project: str, target_ip: str, incident_id: str) -> dict:
    name = rule_name(target_ip, incident_id)
    deleted = []
    for rule in [name, f"{name}-egress"]:
        try:
            service.firewalls().delete(project=project, firewall=rule).execute()
            deleted.append(rule)
        except Exception:
            pass
    return {"status": "RELEASED", "deleted_rules": deleted}


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
            result = isolate(service, project, target_ip, incident_id, network)
        elif action == "release":
            result = release(service, project, target_ip, incident_id)
        else:
            return json.dumps({"error": f"unknown action: {action}"}), 400, {"Content-Type": "application/json"}

        result["incident_id"] = incident_id
        result["target_ip"]   = target_ip
        return json.dumps(result), 200, {"Content-Type": "application/json"}

    except Exception as e:
        body = json.dumps({"incident_id": incident_id, "status": "FAILED", "detail": str(e)})
        return body, 500, {"Content-Type": "application/json"}

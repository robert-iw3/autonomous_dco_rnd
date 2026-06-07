"""
nexus-aws-block-ip -- Lambda function
Blocks a source IP via VPC Network ACL deny rules (not per-instance -- affects
all traffic entering/leaving the VPC from that IP).

Payload schema:
  {
    "incident_id": "INC-XXXX",
    "target_ip":   "1.2.3.4",         # IP to block (attacker)
    "vpc_id":      "vpc-xxxxxxxx",     # optional override
    "action":      "block" | "unblock"
  }
"""

import json
import os
import boto3

ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION", "us-east-1"))
DEFAULT_VPC_ID = os.environ.get("VPC_ID", "")

# NACL rule numbers: 100-199 reserved for Nexus auto-block rules
RULE_NUMBER_INBOUND_BASE  = 100
RULE_NUMBER_OUTBOUND_BASE = 150


def get_main_nacl(vpc_id: str) -> str:
    """Return the main NACL ID for the VPC."""
    resp = ec2.describe_network_acls(
        Filters=[
            {"Name": "vpc-id",    "Values": [vpc_id]},
            {"Name": "default",   "Values": ["true"]},
        ]
    )
    return resp["NetworkAcls"][0]["NetworkAclId"]


def find_free_rule_number(nacl_id: str, base: int, is_egress: bool) -> int:
    """Find the next free rule number starting from base."""
    resp = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    used = {
        e["RuleNumber"]
        for e in resp["NetworkAcls"][0]["Entries"]
        if e["Egress"] == is_egress and base <= e["RuleNumber"] < base + 50
    }
    for n in range(base, base + 50):
        if n not in used:
            return n
    raise RuntimeError("No free NACL rule numbers in range")


def block_ip(incident_id: str, target_ip: str, vpc_id: str) -> dict:
    nacl_id = get_main_nacl(vpc_id)

    inbound_rule  = find_free_rule_number(nacl_id, RULE_NUMBER_INBOUND_BASE,  False)
    outbound_rule = find_free_rule_number(nacl_id, RULE_NUMBER_OUTBOUND_BASE, True)

    for rule_num, egress in [(inbound_rule, False), (outbound_rule, True)]:
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=rule_num,
            Protocol="-1",
            RuleAction="deny",
            Egress=egress,
            CidrBlock=f"{target_ip}/32",
        )

    # Tag NACL for audit
    ec2.create_tags(
        Resources=[nacl_id],
        Tags=[{
            "Key": f"nexus:block-{target_ip.replace('.', '_')}-{incident_id}",
            "Value": f"{inbound_rule},{outbound_rule}"
        }]
    )

    return {
        "nacl_id": nacl_id,
        "inbound_rule": inbound_rule,
        "outbound_rule": outbound_rule,
        "blocked_ip": target_ip,
    }


def unblock_ip(incident_id: str, target_ip: str, vpc_id: str) -> dict:
    nacl_id = get_main_nacl(vpc_id)
    resp = ec2.describe_network_acls(NetworkAclIds=[nacl_id])

    removed = []
    for entry in resp["NetworkAcls"][0]["Entries"]:
        if entry.get("CidrBlock") == f"{target_ip}/32" and entry.get("RuleAction") == "deny":
            ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=entry["RuleNumber"],
                Egress=entry["Egress"],
            )
            removed.append(entry["RuleNumber"])

    return {"nacl_id": nacl_id, "removed_rules": removed, "unblocked_ip": target_ip}


def handler(event, context):
    print(f"[block_ip] event={json.dumps(event)}")

    incident_id = event.get("incident_id", "UNKNOWN")
    target_ip   = event.get("target_ip", "")
    vpc_id      = event.get("vpc_id") or DEFAULT_VPC_ID
    action      = event.get("action", "block")

    if not target_ip:
        return {"incident_id": incident_id, "status": "FAILED", "detail": "target_ip required"}
    if not vpc_id:
        return {"incident_id": incident_id, "status": "FAILED", "detail": "vpc_id required"}

    try:
        if action == "block":
            detail = block_ip(incident_id, target_ip, vpc_id)
            return {"incident_id": incident_id, "status": "BLOCKED", **detail}
        elif action == "unblock":
            detail = unblock_ip(incident_id, target_ip, vpc_id)
            return {"incident_id": incident_id, "status": "UNBLOCKED", **detail}
        else:
            return {"incident_id": incident_id, "status": "FAILED", "detail": f"Unknown action: {action}"}
    except Exception as e:
        print(f"[block_ip] error: {e}")
        return {"incident_id": incident_id, "status": "FAILED", "detail": str(e)}

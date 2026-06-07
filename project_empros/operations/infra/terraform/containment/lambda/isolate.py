"""
nexus-aws-isolate -- Lambda function
Isolates an EC2 instance by attaching a quarantine Security Group that denies
all inbound/outbound traffic except the Nexus management CIDR.

Invoked by:
  1. EventBridge on GuardDuty HIGH/CRITICAL findings (auto-response)
  2. n8n Cloud_Containment workflow via Lambda Function URL (SOAR-directed)
  3. worker_soar directly via Lambda Function URL (aws_containment_v1 provider)

Payload schema (JSON):
  {
    "incident_id":   "INC-XXXX",
    "target_ip":     "1.2.3.4",          # remote/attacker IP or instance private IP
    "instance_id":   "i-0123456789abcdef" # optional -- if known from GuardDuty
    "action":        "isolate" | "release",
    "source":        "n8n" | "worker_soar" | "guardduty_auto"
  }

Returns (JSON):
  {
    "incident_id": "...",
    "status":      "CONTAINED" | "RELEASED" | "FAILED",
    "instance_id": "...",
    "quarantine_sg_id": "...",
    "detail":      "..."
  }
"""

import json
import os
import hashlib
import hmac
import time
import boto3
import urllib.request
import urllib.error

ec2 = boto3.client("ec2", region_name=os.environ.get("AWS_REGION", "us-east-1"))

QUARANTINE_SG_PREFIX = os.environ.get("QUARANTINE_SG_PREFIX", "NEXUS-QUARANTINE")
N8N_CALLBACK_URL = os.environ.get("N8N_CALLBACK_URL", "")
HMAC_SECRET = os.environ.get("NEXUS_HMAC_SECRET", "").encode()
# Management CIDR -- Nexus analytics node must retain access
MGMT_CIDR = os.environ.get("NEXUS_MGMT_CIDR", "10.0.0.0/8")


def get_instance_by_ip(ip: str) -> dict | None:
    """Resolve instance ID and VPC from private IP."""
    try:
        resp = ec2.describe_instances(
            Filters=[{"Name": "private-ip-address", "Values": [ip]}]
        )
        for r in resp["Reservations"]:
            for inst in r["Instances"]:
                return inst
    except Exception:
        pass
    return None


def get_or_create_quarantine_sg(vpc_id: str, incident_id: str) -> str:
    """Get or create the quarantine SG for this VPC."""
    name = f"{QUARANTINE_SG_PREFIX}-{vpc_id}"
    # Check if it exists
    resp = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [name]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    if resp["SecurityGroups"]:
        return resp["SecurityGroups"][0]["GroupId"]

    # Create quarantine SG -- deny all except management CIDR
    sg = ec2.create_security_group(
        GroupName=name,
        Description=f"Nexus quarantine SG -- deny all except management ({incident_id})",
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "security-group",
            "Tags": [
                {"Key": "Name", "Value": name},
                {"Key": "nexus:managed", "Value": "true"},
                {"Key": "nexus:component", "Value": "containment"},
            ]
        }]
    )
    sg_id = sg["GroupId"]

    # Remove the default outbound allow-all
    ec2.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )

    # Allow management CIDR inbound SSH/WinRM for remediation
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": MGMT_CIDR, "Description": "Nexus management SSH"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 5985,
                "ToPort": 5986,
                "IpRanges": [{"CidrIp": MGMT_CIDR, "Description": "Nexus management WinRM"}],
            },
        ]
    )
    # Allow management egress only
    ec2.authorize_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": MGMT_CIDR, "Description": "Nexus management egress"}],
        }]
    )

    return sg_id


def isolate_instance(instance: dict, incident_id: str) -> dict:
    """Replace all SGs with the quarantine SG."""
    instance_id = instance["InstanceId"]
    vpc_id = instance["VpcId"]

    original_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
    quarantine_sg_id = get_or_create_quarantine_sg(vpc_id, incident_id)

    # Tag original SGs for restore
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": f"nexus:pre-isolation-sgs-{incident_id}", "Value": ",".join(original_sgs)},
            {"Key": "nexus:isolated", "Value": "true"},
            {"Key": "nexus:incident", "Value": incident_id},
        ]
    )

    # Replace all SGs with quarantine SG
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[quarantine_sg_id]
    )

    return {"instance_id": instance_id, "quarantine_sg_id": quarantine_sg_id, "original_sgs": original_sgs}


def release_instance(instance: dict, incident_id: str) -> dict:
    """Restore original SGs."""
    instance_id = instance["InstanceId"]

    # Find pre-isolation SG tag
    original_sgs_tag = next(
        (t["Value"] for t in instance.get("Tags", [])
         if t["Key"] == f"nexus:pre-isolation-sgs-{incident_id}"),
        None
    )
    if not original_sgs_tag:
        return {"instance_id": instance_id, "status": "no_isolation_record"}

    original_sgs = [s for s in original_sgs_tag.split(",") if s]
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=original_sgs)

    # Clean up isolation tags
    ec2.delete_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": f"nexus:pre-isolation-sgs-{incident_id}"},
            {"Key": "nexus:isolated"},
            {"Key": "nexus:incident"},
        ]
    )
    return {"instance_id": instance_id, "status": "released", "restored_sgs": original_sgs}


def send_callback(result: dict) -> None:
    """POST result to n8n callback URL with HMAC signature."""
    if not N8N_CALLBACK_URL:
        return
    try:
        body = json.dumps(result).encode()
        sig = hmac.new(HMAC_SECRET, body + str(int(time.time())).encode(), hashlib.sha256).hexdigest()
        req = urllib.request.Request(
            N8N_CALLBACK_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Nexus-Signature": sig,
                "X-Nexus-Component": "aws-containment",
            },
            method="POST"
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[callback] failed: {e}")


def handler(event, context):
    print(f"[isolate] event={json.dumps(event)}")

    incident_id = event.get("incident_id", "UNKNOWN")
    target_ip   = event.get("target_ip", "")
    instance_id = event.get("instance_id")
    action      = event.get("action", "isolate")

    result = {"incident_id": incident_id, "target_ip": target_ip, "status": "FAILED", "detail": ""}

    try:
        # Resolve instance
        instance = None
        if instance_id:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            for r in resp["Reservations"]:
                for inst in r["Instances"]:
                    instance = inst
        if not instance and target_ip:
            instance = get_instance_by_ip(target_ip)

        if not instance:
            result["detail"] = f"No EC2 instance found for ip={target_ip} id={instance_id}"
            send_callback(result)
            return result

        if action == "isolate":
            detail = isolate_instance(instance, incident_id)
            result.update({"status": "CONTAINED", "detail": f"SG replaced with quarantine", **detail})
        elif action == "release":
            detail = release_instance(instance, incident_id)
            result.update({"status": "RELEASED", **detail})
        else:
            result["detail"] = f"Unknown action: {action}"

    except Exception as e:
        result["detail"] = str(e)
        print(f"[isolate] error: {e}")

    send_callback(result)
    print(f"[isolate] result={json.dumps(result)}")
    return result

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
    "action":        "isolate" | "release" | "snapshot_volume" | "revoke_instance_role",
    "source":        "n8n" | "worker_soar" | "guardduty_auto"
  }

Returns a Lambda URL envelope {"statusCode": N, "body": <result JSON>} so that
dispatch failures are visible to the caller's HTTP status check: 200 on success,
400 unknown action, 404 no instance resolved, 500 execution error. A plain-dict
return would always be served as HTTP 200 -- a failed containment step would be
recorded as done.

Result body:
  {
    "incident_id": "...",
    "status":      "CONTAINED" | "RELEASED" | "SNAPSHOTTED" | "ROLE_REVOKED" | "FAILED",
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


def snapshot_volumes(instance: dict, incident_id: str) -> dict:
    """Evidence-first: snapshot every attached EBS volume, tagged to the incident."""
    instance_id = instance["InstanceId"]
    volume_ids = [
        bdm["Ebs"]["VolumeId"]
        for bdm in instance.get("BlockDeviceMappings", [])
        if "Ebs" in bdm and bdm["Ebs"].get("VolumeId")
    ]
    if not volume_ids:
        raise RuntimeError(f"no EBS volumes attached to {instance_id}")
    snapshot_ids = []
    for vol_id in volume_ids:
        snap = ec2.create_snapshot(
            VolumeId=vol_id,
            Description=f"Nexus IR evidence snapshot {incident_id} ({instance_id})",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "nexus:managed", "Value": "true"},
                    {"Key": "nexus:component", "Value": "containment"},
                    {"Key": "nexus:incident", "Value": incident_id},
                    {"Key": "nexus:source-instance", "Value": instance_id},
                ],
            }],
        )
        snapshot_ids.append(snap["SnapshotId"])
    return {"instance_id": instance_id, "volume_ids": volume_ids,
            "snapshot_ids": snapshot_ids}


def revoke_instance_role(instance: dict, incident_id: str) -> dict:
    """Strip the instance's IAM role so stolen instance credentials stop minting.

    The association id is tagged onto the instance for operator-driven restore;
    the existing STS sessions expire on their own (max 6h)."""
    instance_id = instance["InstanceId"]
    assoc = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}]
    )["IamInstanceProfileAssociations"]
    if not assoc:
        return {"instance_id": instance_id, "status": "no_instance_profile"}
    profile_arn = assoc[0]["IamInstanceProfile"]["Arn"]
    ec2.disassociate_iam_instance_profile(AssociationId=assoc[0]["AssociationId"])
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": f"nexus:pre-revocation-profile-{incident_id}", "Value": profile_arn},
            {"Key": "nexus:incident", "Value": incident_id},
        ],
    )
    return {"instance_id": instance_id, "revoked_profile_arn": profile_arn}


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


def _respond(status_code: int, result: dict):
    """Lambda URL envelope: the HTTP status must reflect the real outcome."""
    send_callback(result)
    print(f"[isolate] status={status_code} result={json.dumps(result)}")
    return {"statusCode": status_code, "body": json.dumps(result),
            "headers": {"Content-Type": "application/json"}}


_ACTIONS = {
    "isolate": (isolate_instance, "CONTAINED"),
    "release": (release_instance, "RELEASED"),
    "snapshot_volume": (snapshot_volumes, "SNAPSHOTTED"),
    "revoke_instance_role": (revoke_instance_role, "ROLE_REVOKED"),
}


def handler(event, context):
    print(f"[isolate] event={json.dumps(event)}")

    # Lambda URL invocations wrap the payload in a body string
    if isinstance(event.get("body"), str):
        try:
            event = {**event, **json.loads(event["body"])}
        except json.JSONDecodeError:
            pass

    incident_id = event.get("incident_id", "UNKNOWN")
    target_ip   = event.get("target_ip", "")
    instance_id = event.get("instance_id")
    action      = event.get("action", "isolate")

    result = {"incident_id": incident_id, "target_ip": target_ip,
              "action": action, "status": "FAILED", "detail": ""}

    if action not in _ACTIONS:
        result["detail"] = f"Unknown action: {action}"
        return _respond(400, result)

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
            return _respond(404, result)

        fn, ok_status = _ACTIONS[action]
        detail = fn(instance, incident_id)
        result.update({"status": ok_status, **detail})
        return _respond(200, result)

    except Exception as e:
        result["detail"] = str(e)
        print(f"[isolate] error: {e}")
        return _respond(500, result)

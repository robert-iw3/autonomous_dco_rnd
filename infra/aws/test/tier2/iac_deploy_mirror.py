"""
Tier-2 logic mirror of the deploy/ IaC contract.
"""

# ---------------------------------------------------------------------------
# SHARED across all three connectors (verified: the IAM action set and the
# core posture controls are identical; only names/scoping differ).
# ---------------------------------------------------------------------------

# IAM actions the connector calls at runtime -> the execution policy MUST grant
# (a superset of) these. src: aws_iam_policy.connector_execution_policy.
REQUIRED_RUNTIME_ACTIONS = {
    "sqs:ReceiveMessage",
    "sqs:DeleteMessage",
    "sqs:ChangeMessageVisibility",
    "s3:GetObject",
    "dynamodb:GetItem",
    "dynamodb:BatchGetItem",
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
}

# Granted but not strictly required by a read-only puller -- surfaced as a
# least-privilege observation, never a hard failure.
KNOWN_OVERGRANTS = {"kms:GenerateDataKey"}

# Posture values asserted via type-based discovery (not by resource name).
POSTURE = {
    "s3_sse_algorithm": "aws:kms",
    "s3_sse_cmk_ref": "aws_kms_key.nexus_key.arn",
    "kms_key_rotation_enabled": "true",
    "sqs_redrive_max_receive_count": "5",
}

# ---------------------------------------------------------------------------
# PER-CONNECTOR specifics.
#
# source_suffix: the S3 object suffix the bucket notification filters on == the
#   *source* log format this connector ingests. This is DISTINCT from the
#   connector's egress to Nexus (always Parquet, tier0 CONTENT_TYPE) -- the
#   connector reads source logs, transforms, and re-emits the unified 31-col
#   Parquet batch. Conflating the two was wrong in the first tier2 cut.
#   vpc       -> VPC Flow Logs delivered as Parquet  (.parquet)
#   cloudtrail-> CloudTrail delivers gzip'd JSON      (.json.gz)   [from run output]
#   guardduty -> GuardDuty findings export as JSONL   (.jsonl.gz)  [from run output]
#
# metadata_key: the hash_key the connector keys its DynamoDB context lookup by.
#   vpc keys vpc_id; cloudtrail/guardduty key iam_arn (identity_metadata).
#   NOTE: the guardduty connector passes EMPTY metadata (tier0), so its tables
#   are provisioned-but-unused -- the membership check stays informational.
#
# has_flowlog_stackset: only vpc ships the AWS::EC2::FlowLog StackSet.
# emulator_unsupported: services moto can't faithfully emulate -> convergence
#   apply is skipped for that connector (fidelity ceiling), deferred to a gated
#   real-AWS run.
# ---------------------------------------------------------------------------
CONNECTOR_PROFILE = {
    "vpc": {
        "source_suffix": ".parquet",
        "metadata_key": "vpc_id",
        "has_flowlog_stackset": True,
        "emulator_unsupported": [],
    },
    "cloudtrail": {
        "source_suffix": ".json.gz",
        "metadata_key": "iam_arn",
        "has_flowlog_stackset": False,
        "emulator_unsupported": [],
    },
    "guardduty": {
        "source_suffix": ".jsonl.gz",
        "metadata_key": "iam_arn",
        "has_flowlog_stackset": False,
        # data "aws_guardduty_detector" + GuardDuty APIs are not faithfully
        # emulated by moto -> convergence apply skipped, behavior deferred.
        "emulator_unsupported": ["guardduty"],
    },
}

# ---------------------------------------------------------------------------
# CloudFormation StackSet FlowLog invariants (vpc only).
# CORRECTED: in CloudFormation, FileFormat + HiveCompatiblePartitions live under
# DestinationOptions -- NOT as top-level Properties, and there is no
# "LogFileNameFormat" property at all. The first tier2 cut mirrored the
# template's *invalid* top-level names and so passed on a non-deployable
# template; cfn-lint (E3002) is what caught it. These assertions now require
# the valid shape, so they (correctly) fail until the template is fixed.
# ---------------------------------------------------------------------------
FLOWLOG = {
    "cfn_type": "AWS::EC2::FlowLog",
    "traffic_type": "ALL",
    "log_destination_type": "s3",
    "destination_file_format": "parquet",        # DestinationOptions.FileFormat
    "hive_compatible_partitions": True,           # DestinationOptions.HiveCompatiblePartitions
    "resource_type": "VPC",
    "log_format_requires": "${vpc-id}",
}

# ---------------------------------------------------------------------------
# checkov gate: ENFORCE EVERYTHING except a small set of checks that are
# genuinely not-applicable to this architecture, each with a written rationale.
# This is the opposite of an allowlist -- new categories fail by default; we do
# not silently tolerate real findings. The VPC stack passes this clean after
# the source fixes; cloudtrail/guardduty will (correctly) fail until the same
# fixes are applied to their stacks.
# ---------------------------------------------------------------------------
CHECKOV_SKIP = {
    "CKV_AWS_18":   "S3 server access logging handled at the org log-archive level, not per-bucket",
    "CKV_AWS_117":  "orchestrator Lambda calls AWS control-plane APIs only; no VPC attachment needed",
    "CKV_AWS_144":  "single-region telemetry store; cross-region replication is out of scope",
    "CKV_AWS_272":  "Lambda code-signing not used in this pipeline",
    "CKV2_AWS_57":  "Auth token rotation managed out-of-band via CI/CD pipeline; Lambda-based rotation is not appropriate for this bearer token pattern",
}
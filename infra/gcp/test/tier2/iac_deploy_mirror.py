"""
Tier-2 logic mirror of the GCP deploy/ IaC contract.
"""

# ---------------------------------------------------------------------------
# PER-CONNECTOR specifics.
#
# subscription_tf_name: Terraform resource label for the connector's
#   Pub/Sub subscription.
#
# topic_tf_name: Terraform resource label for the connector's Pub/Sub topic.
#
# has_dlq: vpc provisions a dead-letter queue topic + subscription.
#
# has_dlq_drain: vpc provisions a drain subscription on the DLQ topic.
#
# dlq_drain_subscription_tf_name: TF label for the DLQ drain subscription.
#
# dlq_alert_tf_name: TF label for the monitoring alert on DLQ message count.
#
# has_logging_sink: audit/vpc route logs via google_logging_project_sink.
#
# has_scc_notification: only scc uses google_scc_notification_config.
#
# sink_tf_name: TF label for the logging sink (if any).
#
# sink_log_filter_contains: substring the logging sink's filter must contain.
#
# required_retry_policy: all three connectors must declare retry_policy.
#
# has_connector_sa: all connectors provision a dedicated service account.
#
# connector_sa_tf_name: TF label for the service account.
#
# has_secret_manager: all connectors provision a Secret Manager secret.
#
# secret_tf_name: TF label for the auth_token secret.
#
# has_monitoring_alert: all connectors provision a queue-age alert.
#
# alert_tf_name: TF label for the queue-age monitoring alert policy.
# ---------------------------------------------------------------------------
CONNECTOR_PROFILE = {
    "audit": {
        "subscription_tf_name":          "cloud_audit_sub",
        "topic_tf_name":                 "cloud_audit",
        "has_dlq":                       False,
        "has_dlq_drain":                 False,
        "dlq_drain_subscription_tf_name": None,
        "dlq_alert_tf_name":             None,
        "has_logging_sink":              True,
        "has_scc_notification":          False,
        "sink_tf_name":                  "cloud_audit_sink",
        "sink_log_filter_contains":      "cloudaudit.googleapis.com",
        "required_retry_policy":         True,
        "has_connector_sa":              True,
        "connector_sa_tf_name":          "connector",
        "has_secret_manager":            True,
        "secret_tf_name":                "auth_token",
        "has_monitoring_alert":          True,
        "alert_tf_name":                 "queue_age",
    },
    "scc": {
        "subscription_tf_name":          "scc_sub",
        "topic_tf_name":                 "scc_findings",
        "has_dlq":                       False,
        "has_dlq_drain":                 False,
        "dlq_drain_subscription_tf_name": None,
        "dlq_alert_tf_name":             None,
        "has_logging_sink":              False,
        "has_scc_notification":          True,
        "sink_tf_name":                  None,
        "sink_log_filter_contains":      None,
        "required_retry_policy":         True,
        "has_connector_sa":              True,
        "connector_sa_tf_name":          "connector",
        "has_secret_manager":            True,
        "secret_tf_name":                "auth_token",
        "has_monitoring_alert":          True,
        "alert_tf_name":                 "queue_age",
    },
    "vpc": {
        "subscription_tf_name":          "vpc_flows",
        "topic_tf_name":                 "vpc_flows",
        "has_dlq":                       True,
        "has_dlq_drain":                 True,
        "dlq_drain_subscription_tf_name": "dlq_drain",
        "dlq_alert_tf_name":             "dlq_messages",
        "has_logging_sink":              True,
        "has_scc_notification":          False,
        "sink_tf_name":                  "vpc_flows",
        "sink_log_filter_contains":      "vpc_flows",
        "required_retry_policy":         True,
        "has_connector_sa":              True,
        "connector_sa_tf_name":          "connector",
        "has_secret_manager":            True,
        "secret_tf_name":                "auth_token",
        "has_monitoring_alert":          True,
        "alert_tf_name":                 "queue_age",
    },
}

# Pub/Sub subscription posture values asserted across all connectors.
SUBSCRIPTION_POSTURE = {
    "ack_deadline_seconds":       "60",
    "message_retention_duration": "86400s",
}

# Retry policy values asserted when required_retry_policy is True.
RETRY_POSTURE = {
    "minimum_backoff": "10s",
    "maximum_backoff": "600s",
}

# VPC DLQ posture
DLQ_MAX_DELIVERY_ATTEMPTS = "10"

# SCC notification config must filter for active findings only.
SCC_FILTER_ACTIVE = "ACTIVE"

# Required outputs per connector -- read by runtime config at deploy time
# to wire the connector to the provisioned infrastructure.
REQUIRED_OUTPUTS = {
    "audit": {"subscription_id", "topic_id", "sink_writer",
              "service_account_email", "auth_token_secret_id"},
    "scc":   {"subscription_id", "topic_id",
              "service_account_email", "auth_token_secret_id"},
    "vpc":   {"subscription_id", "topic_id", "sink_writer",
              "service_account_email", "auth_token_secret_id", "dlq_subscription_id"},
}

# ---------------------------------------------------------------------------
# checkov gate: enforce everything except checks that are genuinely N/A.
# Every entry must include a rationale; a new check failing by default is a
# deliberate blocker that requires a conscious team decision to skip.
# ---------------------------------------------------------------------------
CHECKOV_SKIP = {
    # CMEK for Pub/Sub topics -- production requirement deferred to shared KMS
    # module. When the org-wide KMS module is available, add kms_key_name to
    # each google_pubsub_topic. Until then CMEK is outside connector scope.
    "CKV_GCP_83": (
        "Pub/Sub topic CMEK requires a shared KMS module not yet integrated; "
        "pending KMS module integration sprint"
    ),
    # CMEK for Secret Manager -- same shared KMS module dependency as above.
    # Add customer_managed_encryption.kms_key_name to each secret's replication
    # block when the org KMS module is available.
    "CKV_GCP_93": (
        "Secret Manager CMEK requires the shared KMS module not yet integrated; "
        "pending KMS module integration sprint"
    ),
}
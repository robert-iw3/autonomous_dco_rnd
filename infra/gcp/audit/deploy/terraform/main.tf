terraform {
  required_version = ">= 1.9"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  # Provide bucket and prefix via terraform init -backend-config flags or a
  # backend.hcl file:
  #   terraform init -backend-config="bucket=nexus-tf-state" \
  #                  -backend-config="prefix=nexus/gcp/audit/production"
  backend "gcs" {}
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# ---------------------------------------------------------------------------
# Pub/Sub
# ---------------------------------------------------------------------------
resource "google_pubsub_topic" "cloud_audit" {
  name   = "${var.project_name}-${var.environment}-audit"
  labels = var.labels
}

resource "google_pubsub_subscription" "cloud_audit_sub" {
  name   = "${var.project_name}-${var.environment}-audit-sub"
  topic  = google_pubsub_topic.cloud_audit.id
  labels = var.labels

  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

# ---------------------------------------------------------------------------
# Logging sink → Pub/Sub
# ---------------------------------------------------------------------------
resource "google_logging_project_sink" "cloud_audit_sink" {
  name        = "${var.project_name}-${var.environment}-audit-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.cloud_audit.id}"
  filter      = "logName:\"cloudaudit.googleapis.com%2Factivity\" OR logName:\"cloudaudit.googleapis.com%2Fdata_access\""

  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "audit_publisher" {
  topic  = google_pubsub_topic.cloud_audit.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.cloud_audit_sink.writer_identity
}

# ---------------------------------------------------------------------------
# Connector service account
# ---------------------------------------------------------------------------
resource "google_service_account" "connector" {
  account_id   = "${var.project_name}-${var.environment}-sa"
  display_name = "Nexus GCP Audit Connector"
  description  = "Service account for the nexus-gcp-audit connector process"
}

resource "google_pubsub_subscription_iam_member" "connector_subscriber" {
  subscription = google_pubsub_subscription.cloud_audit_sub.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.connector.email}"
}

# ---------------------------------------------------------------------------
# Secret Manager: gateway auth token
# ---------------------------------------------------------------------------
resource "google_secret_manager_secret" "auth_token" {
  secret_id = "${var.project_name}-${var.environment}-auth-token"
  labels    = var.labels

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "connector_secret_access" {
  secret_id = google_secret_manager_secret.auth_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.connector.email}"
}

# ---------------------------------------------------------------------------
# Monitoring: alert when messages age past 1h (connector or gateway down)
# ---------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "queue_age" {
  display_name = "${var.project_name}-${var.environment}-audit-queue-age"
  combiner     = "OR"

  conditions {
    display_name = "Oldest undelivered message age > 1h"

    condition_threshold {
      filter          = "metric.type = \"pubsub.googleapis.com/subscription/oldest_undelivered_message_age\" AND resource.labels.subscription_id = \"${google_pubsub_subscription.cloud_audit_sub.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 3600
      duration        = "300s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  notification_channels = var.alert_notification_channels
  user_labels           = var.labels
}

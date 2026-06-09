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
  #                  -backend-config="prefix=nexus/gcp/scc/production"
  backend "gcs" {}
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# ---------------------------------------------------------------------------
# Pub/Sub
# ---------------------------------------------------------------------------
resource "google_pubsub_topic" "scc_findings" {
  name   = "${var.project_name}-${var.environment}-scc"
  labels = var.labels
}

resource "google_pubsub_subscription" "scc_sub" {
  name   = "${var.project_name}-${var.environment}-scc-sub"
  topic  = google_pubsub_topic.scc_findings.id
  labels = var.labels

  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

# ---------------------------------------------------------------------------
# SCC notification config routes active findings to the Pub/Sub topic.
# The deploying principal must have securitycenter.notificationConfigEditor
# at the organization level before applying this stack.
# ---------------------------------------------------------------------------
resource "google_scc_notification_config" "scc_to_pubsub" {
  config_id    = "nexus-scc-router"
  organization = var.gcp_organization_id
  description  = "Routes active SCC findings to the Nexus processing pipeline"
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "state = \"ACTIVE\""
  }
}

# ---------------------------------------------------------------------------
# Connector service account
# ---------------------------------------------------------------------------
resource "google_service_account" "connector" {
  account_id   = "${var.project_name}-${var.environment}-sa"
  display_name = "Nexus GCP SCC Connector"
  description  = "Service account for the nexus-gcp-scc connector process"
}

resource "google_pubsub_subscription_iam_member" "connector_subscriber" {
  subscription = google_pubsub_subscription.scc_sub.name
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
  display_name = "${var.project_name}-${var.environment}-scc-queue-age"
  combiner     = "OR"

  conditions {
    display_name = "Oldest undelivered message age > 1h"

    condition_threshold {
      filter          = "metric.type = \"pubsub.googleapis.com/subscription/oldest_undelivered_message_age\" AND resource.labels.subscription_id = \"${google_pubsub_subscription.scc_sub.name}\""
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

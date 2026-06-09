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
  #                  -backend-config="prefix=nexus/gcp/vpc/production"
  backend "gcs" {}
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# ---------------------------------------------------------------------------
# Pub/Sub: main topic + pull subscription
# ---------------------------------------------------------------------------
resource "google_pubsub_topic" "vpc_flows" {
  name   = "${var.project_name}-${var.environment}-flows"
  labels = var.labels
}

resource "google_pubsub_subscription" "vpc_flows" {
  name   = "${var.project_name}-${var.environment}-sub"
  topic  = google_pubsub_topic.vpc_flows.id
  labels = var.labels

  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dlq.id
    max_delivery_attempts = 10
  }
}

# ---------------------------------------------------------------------------
# Dead-letter queue
# ---------------------------------------------------------------------------
resource "google_pubsub_topic" "dlq" {
  name   = "${var.project_name}-${var.environment}-dlq"
  labels = var.labels
}

# Drain subscription allows ops to inspect and replay dead-letter messages.
resource "google_pubsub_subscription" "dlq_drain" {
  name   = "${var.project_name}-${var.environment}-dlq-sub"
  topic  = google_pubsub_topic.dlq.id
  labels = var.labels

  ack_deadline_seconds       = 600
  message_retention_duration = "604800s"
}

# ---------------------------------------------------------------------------
# Logging sink → Pub/Sub
# ---------------------------------------------------------------------------
resource "google_logging_project_sink" "vpc_flows" {
  name        = "${var.project_name}-${var.environment}-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.vpc_flows.id}"
  filter      = "log_id(\"compute.googleapis.com/vpc_flows\")"

  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.vpc_flows.id
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.vpc_flows.writer_identity
}

# ---------------------------------------------------------------------------
# Connector service account
# ---------------------------------------------------------------------------
resource "google_service_account" "connector" {
  account_id   = "${var.project_name}-${var.environment}-sa"
  display_name = "Nexus GCP VPC Connector"
  description  = "Service account for the nexus-gcp-vpc connector process"
}

resource "google_pubsub_subscription_iam_member" "connector_subscriber" {
  subscription = google_pubsub_subscription.vpc_flows.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.connector.email}"
}

resource "google_pubsub_subscription_iam_member" "connector_dlq_subscriber" {
  subscription = google_pubsub_subscription.dlq_drain.name
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
# Monitoring: queue age + DLQ drain alerts
# ---------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "queue_age" {
  display_name = "${var.project_name}-${var.environment}-vpc-queue-age"
  combiner     = "OR"

  conditions {
    display_name = "Oldest undelivered message age > 1h"

    condition_threshold {
      filter          = "metric.type = \"pubsub.googleapis.com/subscription/oldest_undelivered_message_age\" AND resource.labels.subscription_id = \"${google_pubsub_subscription.vpc_flows.name}\""
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

resource "google_monitoring_alert_policy" "dlq_messages" {
  display_name = "${var.project_name}-${var.environment}-vpc-dlq-nonempty"
  combiner     = "OR"

  conditions {
    display_name = "Dead-letter queue has undelivered messages"

    condition_threshold {
      filter          = "metric.type = \"pubsub.googleapis.com/subscription/num_undelivered_messages\" AND resource.labels.subscription_id = \"${google_pubsub_subscription.dlq_drain.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  notification_channels = var.alert_notification_channels
  user_labels           = var.labels
}

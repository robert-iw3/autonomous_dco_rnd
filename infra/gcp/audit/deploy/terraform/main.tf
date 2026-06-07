terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

resource "google_pubsub_topic" "cloud_audit" {
  name = "${var.project_name}-${var.environment}-audit"
}

resource "google_pubsub_subscription" "cloud_audit_sub" {
  name  = "${var.project_name}-${var.environment}-audit-sub"
  topic = google_pubsub_topic.cloud_audit.id
  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

resource "google_logging_project_sink" "cloud_audit_sink" {
  name        = "${var.project_name}-${var.environment}-audit-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.cloud_audit.id}"
  # Capture Admin Activity and Data Access for the entire project
  filter      = "logName:\"cloudaudit.googleapis.com%2Factivity\" OR logName:\"cloudaudit.googleapis.com%2Fdata_access\""
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "audit_publisher" {
  topic  = google_pubsub_topic.cloud_audit.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.cloud_audit_sink.writer_identity
}
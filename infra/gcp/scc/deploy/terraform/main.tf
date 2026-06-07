terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

resource "google_pubsub_topic" "scc_findings" {
  name = "${var.project_name}-${var.environment}-scc"
}

resource "google_pubsub_subscription" "scc_sub" {
  name  = "${var.project_name}-${var.environment}-scc-sub"
  topic = google_pubsub_topic.scc_findings.id
  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"
}

# SCC Notification Config explicitly routes active findings to Pub/Sub
resource "google_scc_notification_config" "scc_to_pubsub" {
  config_id    = "nexus-scc-router"
  organization = var.gcp_organization_id
  description  = "Routes active SCC findings to the Nexus processing pipeline"
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = "state = \"ACTIVE\""
  }
}
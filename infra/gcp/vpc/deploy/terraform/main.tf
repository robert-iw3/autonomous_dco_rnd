terraform {
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

# Topic that VPC flow logs are routed to.
resource "google_pubsub_topic" "vpc_flows" {
  name = "${var.project_name}-${var.environment}-flows"
}

# Pull subscription the Rust connector drains. ack_deadline must comfortably
# exceed the connector's batch_timeout so in-flight batches are not redelivered.
resource "google_pubsub_subscription" "vpc_flows" {
  name  = "${var.project_name}-${var.environment}-sub"
  topic = google_pubsub_topic.vpc_flows.id

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

resource "google_pubsub_topic" "dlq" {
  name = "${var.project_name}-${var.environment}-dlq"
}

# Project-wide Logging sink: route VPC flow log entries to the topic.
resource "google_logging_project_sink" "vpc_flows" {
  name        = "${var.project_name}-${var.environment}-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.vpc_flows.id}"
  filter      = "log_id(\"compute.googleapis.com/vpc_flows\")"

  unique_writer_identity = true
}

# Allow the sink's writer identity to publish to the topic.
resource "google_pubsub_topic_iam_member" "sink_publisher" {
  topic  = google_pubsub_topic.vpc_flows.id
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.vpc_flows.writer_identity
}

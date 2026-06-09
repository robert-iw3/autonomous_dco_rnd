output "subscription_id" {
  value = google_pubsub_subscription.vpc_flows.name
}

output "topic_id" {
  value = google_pubsub_topic.vpc_flows.id
}

output "sink_writer" {
  value = google_logging_project_sink.vpc_flows.writer_identity
}

output "service_account_email" {
  value = google_service_account.connector.email
}

output "auth_token_secret_id" {
  value = google_secret_manager_secret.auth_token.id
}

output "dlq_subscription_id" {
  value = google_pubsub_subscription.dlq_drain.name
}

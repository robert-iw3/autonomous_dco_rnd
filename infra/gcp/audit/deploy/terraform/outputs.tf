output "subscription_id" {
  value = google_pubsub_subscription.cloud_audit_sub.name
}

output "topic_id" {
  value = google_pubsub_topic.cloud_audit.id
}

output "sink_writer" {
  value = google_logging_project_sink.cloud_audit_sink.writer_identity
}

output "service_account_email" {
  value = google_service_account.connector.email
}

output "auth_token_secret_id" {
  value = google_secret_manager_secret.auth_token.id
}

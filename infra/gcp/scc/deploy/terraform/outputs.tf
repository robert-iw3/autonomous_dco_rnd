output "subscription_id" {
  value = google_pubsub_subscription.scc_sub.name
}

output "topic_id" {
  value = google_pubsub_topic.scc_findings.id
}

output "service_account_email" {
  value = google_service_account.connector.email
}

output "auth_token_secret_id" {
  value = google_secret_manager_secret.auth_token.id
}

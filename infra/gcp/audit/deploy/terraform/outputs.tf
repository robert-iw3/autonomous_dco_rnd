output "subscription_id"   { value = google_pubsub_subscription.vpc_flows.name }
output "topic_id"          { value = google_pubsub_topic.vpc_flows.id }
output "sink_writer"       { value = google_logging_project_sink.vpc_flows.writer_identity }

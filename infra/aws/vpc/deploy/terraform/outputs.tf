output "s3_bucket_arn" {
  value       = aws_s3_bucket.flow_logs.arn
  description = "VPC Flow Logs collection target S3 bucket ARN"
}

output "sqs_queue_url" {
  value       = aws_sqs_queue.flow_logs_queue.id
  description = "SQS file notifications queue target URL for EKS configuration"
}

output "dlq_url" {
  value       = aws_sqs_queue.flow_logs_dlq.id
  description = "Dead letter queue URL for monitoring"
}

output "dynamodb_table_name" {
  value       = aws_dynamodb_table.metadata_store.name
  description = "Context discovery DynamoDB table name identity"
}

output "kms_key_arn" {
  value       = aws_kms_key.nexus_key.arn
  description = "KMS key ARN for cross-service encryption"
}

output "execution_policy_arn" {
  value       = aws_iam_policy.connector_execution_policy.arn
  description = "IAM policy ARN to attach to the EKS service account role"
}

output "auth_token_secret_arn" {
  value       = aws_secretsmanager_secret.auth_token.arn
  description = "Secrets Manager ARN for the connector bearer token"
}

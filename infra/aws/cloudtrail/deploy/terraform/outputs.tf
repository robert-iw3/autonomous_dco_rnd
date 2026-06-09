output "s3_bucket_arn" {
  value       = aws_s3_bucket.cloudtrail_logs.arn
  description = "CloudTrail collection S3 bucket ARN"
}

output "sqs_queue_url" {
  value       = aws_sqs_queue.cloudtrail_queue.id
  description = "SQS queue URL for EKS pod configuration"
}

output "dlq_url" {
  value       = aws_sqs_queue.cloudtrail_dlq.id
  description = "Dead letter queue URL for monitoring"
}

output "dynamodb_table_name" {
  value       = aws_dynamodb_table.identity_metadata.name
  description = "DynamoDB table name for IAM identity metadata"
}

output "execution_policy_arn" {
  value       = aws_iam_policy.connector_execution_policy.arn
  description = "IAM policy ARN to attach to EKS service account role"
}

output "auth_token_secret_arn" {
  value       = aws_secretsmanager_secret.auth_token.arn
  description = "Secrets Manager ARN for the connector bearer token"
}

output "kms_key_arn" {
  value       = aws_kms_key.nexus_key.arn
  description = "KMS key ARN for cross-service encryption"
}
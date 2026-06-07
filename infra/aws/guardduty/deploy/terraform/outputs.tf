output "s3_bucket_arn" {
  value       = aws_s3_bucket.guardduty_findings.arn
  description = "GuardDuty collection S3 bucket ARN"
}

output "sqs_queue_url" {
  value       = aws_sqs_queue.guardduty_queue.id
  description = "SQS queue URL for EKS pod configuration"
}

output "dlq_url" {
  value       = aws_sqs_queue.guardduty_dlq.id
  description = "Dead letter queue URL for monitoring"
}

output "kms_key_arn" {
  value       = aws_kms_key.nexus_key.arn
  description = "KMS key ARN for cross-service encryption"
}

output "execution_policy_arn" {
  value       = aws_iam_policy.connector_execution_policy.arn
  description = "IAM policy ARN to attach to the EKS service account role"
}
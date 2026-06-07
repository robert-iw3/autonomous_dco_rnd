output "s3_bucket_arn" {
  value       = aws_s3_bucket.flow_logs.arn
  description = "VPC Flow Logs collection target S3 bucket ARN"
}

output "sqs_queue_url" {
  value       = aws_sqs_queue.flow_logs_queue.id
  description = "SQS file notifications queue target URL for EKS configuration"
}

output "dynamodb_table_name" {
  value       = aws_dynamodb_table.metadata_store.name
  description = "Context discovery DynamoDB table name identity"
}
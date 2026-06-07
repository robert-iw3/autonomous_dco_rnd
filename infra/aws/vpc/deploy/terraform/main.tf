provider "aws" {
  region = var.aws_region
}

# ------------------------------------------------------------------------------
# 1. Cryptographic Core (KMS)
# ------------------------------------------------------------------------------
resource "aws_kms_key" "nexus_key" {
  description             = "KMS key for Nexus VPC Flow Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "nexus_key_alias" {
  name          = "alias/${var.project_name}-key"
  target_key_id = aws_kms_key.nexus_key.key_id
}

# ------------------------------------------------------------------------------
# 2. Centralized S3 Bucket for Flow Logs & Lifecycle
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "flow_logs" {
  bucket        = "${var.project_name}-${var.environment}-storage"
  force_destroy = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs_encryption" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.nexus_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "flow_logs_privacy" {
  bucket                  = aws_s3_bucket.flow_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_logs_lifecycle" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    id     = "archive-and-expire"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }
  }
}

# ------------------------------------------------------------------------------
# 3. SQS Processing Queue & Dead Letter Queue (DLQ)
# ------------------------------------------------------------------------------
resource "aws_sqs_queue" "flow_logs_dlq" {
  name                      = "${var.project_name}-${var.environment}-dlq"
  message_retention_seconds = 1209600 # 14 days retention
}

resource "aws_sqs_queue" "flow_logs_queue" {
  name                       = "${var.project_name}-${var.environment}-queue"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 864000 # 10 days retention
  kms_master_key_id          = aws_kms_key.nexus_key.arn

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.flow_logs_dlq.arn
    maxReceiveCount     = 5
  })
}

# Allow S3 bucket to publish notifications to the SQS Queue
resource "aws_sqs_queue_policy" "s3_to_sqs_policy" {
  queue_url = aws_sqs_queue.flow_logs_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.flow_logs_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_s3_bucket.flow_logs.arn
          }
        }
      }
    ]
  })
}

# Hook notifications up for new object creations
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.flow_logs.id

  queue {
    queue_arn     = aws_sqs_queue.flow_logs_queue.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".parquet"
  }
}

# ------------------------------------------------------------------------------
# 4. DynamoDB Metadata & Positive Identifier Inventory Store
# ------------------------------------------------------------------------------
resource "aws_dynamodb_table" "metadata_store" {
  name         = "nexus_cloud_infrastructure_metadata"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "vpc_id"

  attribute {
    name = "vpc_id"
    type = "S"
  }

  tags = {
    Environment = var.environment
    Project     = "Nexus"
  }
}

# ------------------------------------------------------------------------------
# 5. IAM Operational Role Permissions for EKS Pod Assumable Use (IRSA)
# ------------------------------------------------------------------------------
resource "aws_iam_policy" "connector_execution_policy" {
  name        = "${var.project_name}-${var.environment}-execution-policy"
  description = "Least privilege permission profile for the Nexus EKS Rust ETL engine"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility"
        ]
        Resource = aws_sqs_queue.flow_logs_queue.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.flow_logs.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem"
        ]
        Resource = aws_dynamodb_table.metadata_store.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.nexus_key.arn
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 6. Automated Discovery & Enablement (EventBridge -> Lambda)
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "vpc_creation_rule" {
  name        = "${var.project_name}-vpc-discovery"
  description = "Triggers on CreateVpc API calls"

  event_pattern = jsonencode({
    "source"      = ["aws.ec2"],
    "detail-type" = ["AWS API Call via CloudTrail"],
    "detail"      = { "eventName" = ["CreateVpc"] }
  })
}

resource "aws_cloudwatch_event_target" "invoke_lambda" {
  rule      = aws_cloudwatch_event_rule.vpc_creation_rule.name
  target_id = "TriggerVpcEnablement"
  arn       = aws_lambda_function.vpc_orchestrator.arn
}

# Requires an IAM role for the Lambda to execute and write to DynamoDB/StackSets
resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_lambda_function" "vpc_orchestrator" {
  filename      = "orchestrator_payload.zip"
  function_name = "${var.project_name}-vpc-orchestrator"
  role          = aws_iam_role.lambda_exec_role.arn
  handler       = "bootstrap.handler"
  runtime       = "provided.al2023"

  environment {
    variables = {
      TARGET_BUCKET_ARN = aws_s3_bucket.flow_logs.arn
      DYNAMO_TABLE      = aws_dynamodb_table.metadata_store.name
    }
  }
}
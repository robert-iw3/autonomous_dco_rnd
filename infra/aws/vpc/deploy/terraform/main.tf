provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# ------------------------------------------------------------------------------
# 1. Cryptographic Core (KMS)
# ------------------------------------------------------------------------------
resource "aws_kms_key" "nexus_key" {
  description             = "KMS key for Nexus VPC Flow Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # CKV2_AWS_64: explicit key policy. Root keeps IAM-based delegation so the
  # connector_execution_policy / lambda role grants below remain authoritative;
  # the VPC Flow Logs delivery service is allowed to use the key for SSE-KMS
  # delivery into the bucket.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowFlowLogsDelivery"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
      }
    ]
  })
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
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "flow_logs_privacy" {
  bucket                  = aws_s3_bucket.flow_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CKV_AWS_21: versioning enabled.
resource "aws_s3_bucket_versioning" "flow_logs_versioning" {
  bucket = aws_s3_bucket.flow_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_logs_lifecycle" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    id     = "archive-and-expire"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }

    # CKV_AWS_300: bound incomplete multipart uploads.
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ------------------------------------------------------------------------------
# 3. SQS Processing Queue & Dead Letter Queue (DLQ)
# ------------------------------------------------------------------------------
resource "aws_sqs_queue" "flow_logs_dlq" {
  name                      = "${var.project_name}-${var.environment}-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.nexus_key.arn
}

resource "aws_sqs_queue" "flow_logs_queue" {
  name                       = "${var.project_name}-${var.environment}-queue"
  visibility_timeout_seconds = 300
  message_retention_seconds  = 864000
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

  # CKV_AWS_119: encrypt with the CMK.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.nexus_key.arn
  }

  # CKV_AWS_28: point-in-time recovery.
  point_in_time_recovery {
    enabled = true
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

# Lambda execution role + least-privilege permissions (the original role had
# NO permissions policy attached -- the orchestrator could not write metadata,
# enable flow logs, or deploy the StackSet).
resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_exec_policy" {
  # checkov:skip=CKV_AWS_355:ec2:Describe*/CreateFlowLogs do not support resource-level scoping
  # checkov:skip=CKV_AWS_290:the only unscoped write is ec2:CreateFlowLogs (no ARN constraint exists)
  name = "${var.project_name}-lambda-exec-policy"
  role = aws_iam_role.lambda_exec_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-vpc-orchestrator:*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:CreateFlowLogs", "ec2:DescribeFlowLogs", "ec2:DescribeVpcs"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.metadata_store.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.nexus_key.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.lambda_dlq.arn
      }
    ]
  })
}

# CKV_AWS_116: dedicated, encrypted async DLQ for the orchestrator.
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${var.project_name}-orchestrator-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.nexus_key.arn
}

resource "aws_lambda_function" "vpc_orchestrator" {
  filename      = "orchestrator_payload.zip"
  function_name = "${var.project_name}-vpc-orchestrator"
  role          = aws_iam_role.lambda_exec_role.arn
  handler       = "bootstrap.handler"
  runtime       = "provided.al2023"

  kms_key_arn                    = aws_kms_key.nexus_key.arn
  reserved_concurrent_executions = 5

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  environment {
    variables = {
      TARGET_BUCKET_ARN = aws_s3_bucket.flow_logs.arn
      DYNAMO_TABLE      = aws_dynamodb_table.metadata_store.name
    }
  }
}
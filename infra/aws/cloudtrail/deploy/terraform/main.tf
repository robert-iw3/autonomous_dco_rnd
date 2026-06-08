provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "nexus_key" {
  description             = "KMS key for Nexus CloudTrail Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # CKV2_AWS_64: explicit key policy (was missing). Root retains IAM-based
  # delegation; CloudTrail service is allowed to use the key for log delivery.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
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

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.project_name}-${var.environment}-storage"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "cloudtrail_versioning" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_encryption" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.nexus_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_privacy" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_lifecycle" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
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
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_sqs_queue" "cloudtrail_dlq" {
  name                      = "${var.project_name}-${var.environment}-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.nexus_key.arn
}

resource "aws_sqs_queue" "cloudtrail_queue" {
  name                       = "${var.project_name}-${var.environment}-queue"
  visibility_timeout_seconds = 300
  kms_master_key_id          = aws_kms_key.nexus_key.arn
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.cloudtrail_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_policy" "s3_to_sqs_policy" {
  queue_url = aws_sqs_queue.cloudtrail_queue.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.cloudtrail_queue.arn
        Condition = {
          ArnEquals = { "aws:SourceArn" = aws_s3_bucket.cloudtrail_logs.arn }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  queue {
    queue_arn     = aws_sqs_queue.cloudtrail_queue.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".json.gz"
  }
}

resource "aws_dynamodb_table" "identity_metadata" {
  name         = "nexus_cloud_identity_metadata"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "iam_arn"

  attribute {
    name = "iam_arn"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.nexus_key.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Environment = var.environment
    Project     = "Nexus"
  }
}

resource "aws_iam_policy" "connector_execution_policy" {
  name        = "${var.project_name}-${var.environment}-execution-policy"
  description = "Least-privilege permissions for the Nexus CloudTrail ETL engine"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"]
        Resource = aws_sqs_queue.cloudtrail_queue.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:BatchGetItem"]
        Resource = aws_dynamodb_table.identity_metadata.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.nexus_key.arn
      }
    ]
  })
}
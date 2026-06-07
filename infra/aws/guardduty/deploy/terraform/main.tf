provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# --- KMS ---------------------------------------------------------------------

resource "aws_kms_key" "nexus_key" {
  description             = "KMS key for Nexus GuardDuty findings encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

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
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = ["kms:GenerateDataKey"]
        Resource  = "*"
      },
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "nexus_key_alias" {
  name          = "alias/${var.project_name}-key"
  target_key_id = aws_kms_key.nexus_key.key_id
}

# --- S3 Bucket ---------------------------------------------------------------

resource "aws_s3_bucket" "guardduty_findings" {
  bucket        = "${var.project_name}-${var.environment}-storage"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "guardduty_versioning" {
  bucket = aws_s3_bucket.guardduty_findings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_encryption" {
  bucket = aws_s3_bucket.guardduty_findings.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.nexus_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "guardduty_export_policy" {
  bucket = aws_s3_bucket.guardduty_findings.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:GetBucketLocation"
        Resource  = aws_s3_bucket.guardduty_findings.arn
      },
      {
        Effect    = "Allow"
        Principal = { Service = "guardduty.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.guardduty_findings.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "guardduty_privacy" {
  bucket                  = aws_s3_bucket.guardduty_findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "guardduty_lifecycle" {
  bucket = aws_s3_bucket.guardduty_findings.id
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

# --- SQS ---------------------------------------------------------------------

resource "aws_sqs_queue" "guardduty_dlq" {
  name                      = "${var.project_name}-${var.environment}-dlq"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.nexus_key.arn
}

resource "aws_sqs_queue" "guardduty_queue" {
  name                       = "${var.project_name}-${var.environment}-queue"
  visibility_timeout_seconds = 300
  kms_master_key_id          = aws_kms_key.nexus_key.arn
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.guardduty_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_policy" "s3_to_sqs_policy" {
  queue_url = aws_sqs_queue.guardduty_queue.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.guardduty_queue.arn
        Condition = { ArnEquals = { "aws:SourceArn" = aws_s3_bucket.guardduty_findings.arn } }
      }
    ]
  })
}

# Accept both compressed and uncompressed exports
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.guardduty_findings.id

  queue {
    queue_arn     = aws_sqs_queue.guardduty_queue.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".jsonl.gz"
  }

  queue {
    queue_arn     = aws_sqs_queue.guardduty_queue.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".jsonl"
  }
}

# --- GuardDuty Publishing Destination ----------------------------------------

data "aws_guardduty_detector" "current" {}

resource "aws_guardduty_publishing_destination" "s3_export" {
  detector_id     = data.aws_guardduty_detector.current.id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  kms_key_arn     = aws_kms_key.nexus_key.arn

  depends_on = [
    aws_s3_bucket_policy.guardduty_export_policy,
  ]
}

# --- DynamoDB Metadata Tables ------------------------------------------------

resource "aws_dynamodb_table" "infrastructure_metadata" {
  name         = "nexus_cloud_infrastructure_metadata"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "vpc_id"

  attribute {
    name = "vpc_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
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

  point_in_time_recovery {
    enabled = true
  }
}

# --- IAM ---------------------------------------------------------------------

resource "aws_iam_policy" "connector_execution_policy" {
  name        = "${var.project_name}-${var.environment}-execution-policy"
  description = "Least-privilege permissions for the Nexus GuardDuty ETL engine"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"]
        Resource = aws_sqs_queue.guardduty_queue.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.guardduty_findings.arn}/*"
      },
      {
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:BatchGetItem"]
        Resource = [
          aws_dynamodb_table.infrastructure_metadata.arn,
          aws_dynamodb_table.identity_metadata.arn,
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.nexus_key.arn
      }
    ]
  })
}
# ==============================================================================
# AWS Containment Resources
# ==============================================================================

# ── S3 bucket for Lambda deployment packages ───────────────────────────────────
resource "aws_s3_bucket" "lambda_packages" {
  count  = var.enable_aws ? 1 : 0
  bucket = "nexus-containment-lambda-${var.environment}-${data.aws_caller_identity.current[0].account_id}"
  tags   = local.common_tags
}

resource "aws_s3_bucket_versioning" "lambda_packages" {
  count  = var.enable_aws ? 1 : 0
  bucket = aws_s3_bucket.lambda_packages[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "lambda_packages" {
  count                   = var.enable_aws ? 1 : 0
  bucket                  = aws_s3_bucket.lambda_packages[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {
  count = var.enable_aws ? 1 : 0
}

# ── IAM execution role for Lambda ─────────────────────────────────────────────
resource "aws_iam_role" "lambda_containment" {
  count = var.enable_aws ? 1 : 0
  name  = "nexus-containment-lambda-role-${var.environment}"
  tags  = local.common_tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "lambda_containment" {
  count       = var.enable_aws ? 1 : 0
  name        = "nexus-containment-lambda-policy-${var.environment}"
  description = "Allow Lambda to modify EC2 SGs, NACLs, and GuardDuty findings"
  tags        = local.common_tags

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      # EC2 Security Group and NACL modification
      {
        Sid    = "EC2ContainmentActions"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:ModifyInstanceAttribute",
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:CreateTags",
          "ec2:DeleteTags",
        ]
        Resource = "*"
      },
      # GuardDuty findings update
      {
        Sid    = "GuardDutyRespond"
        Effect = "Allow"
        Action = [
          "guardduty:CreateFilter",
          "guardduty:ArchiveFindings",
          "guardduty:UpdateFindingsFeedback",
        ]
        Resource = "*"
      },
      # SSM for retrieving secrets
      {
        Sid    = "SSMSecrets"
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/nexus/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_containment" {
  count      = var.enable_aws ? 1 : 0
  role       = aws_iam_role.lambda_containment[0].name
  policy_arn = aws_iam_policy.lambda_containment[0].arn
}

# ── Lambda deployment package ──────────────────────────────────────────────────
data "archive_file" "isolate_lambda" {
  count       = var.enable_aws ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "/tmp/nexus_containment_lambda.zip"
}

resource "aws_s3_object" "lambda_package" {
  count  = var.enable_aws ? 1 : 0
  bucket = aws_s3_bucket.lambda_packages[0].id
  key    = "containment/lambda-${filemd5(data.archive_file.isolate_lambda[0].output_path)}.zip"
  source = data.archive_file.isolate_lambda[0].output_path
  etag   = filemd5(data.archive_file.isolate_lambda[0].output_path)
}

# ── Lambda: nexus-aws-isolate (EC2 Security Group isolation) ───────────────────
resource "aws_lambda_function" "aws_isolate" {
  count = var.enable_aws ? 1 : 0

  function_name = "nexus-aws-isolate-${var.environment}"
  description   = "Sentinel Nexus: isolate EC2 instance by attaching quarantine SG"
  role          = aws_iam_role.lambda_containment[0].arn
  handler       = "isolate.handler"
  runtime       = "python3.12"
  timeout       = 60
  memory_size   = 256

  s3_bucket = aws_s3_bucket.lambda_packages[0].id
  s3_key    = aws_s3_object.lambda_package[0].key

  environment {
    variables = {
      ENVIRONMENT          = var.environment
      N8N_CALLBACK_URL     = var.n8n_callback_url
      NEXUS_HMAC_SECRET    = var.nexus_shared_secret
      QUARANTINE_SG_PREFIX = "NEXUS-QUARANTINE"
    }
  }

  tags = local.common_tags
}

# Lambda Function URL -- allows n8n (or worker_soar) to invoke via HTTPS
resource "aws_lambda_function_url" "aws_isolate" {
  count              = var.enable_aws ? 1 : 0
  function_name      = aws_lambda_function.aws_isolate[0].function_name
  authorization_type = "AWS_IAM"
}

# ── Lambda: nexus-aws-block-ip (Network ACL deny rule) ────────────────────────
resource "aws_lambda_function" "aws_block_ip" {
  count = var.enable_aws ? 1 : 0

  function_name = "nexus-aws-block-ip-${var.environment}"
  description   = "Sentinel Nexus: block IP via VPC Network ACL deny rule"
  role          = aws_iam_role.lambda_containment[0].arn
  handler       = "block_ip.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 128

  s3_bucket = aws_s3_bucket.lambda_packages[0].id
  s3_key    = aws_s3_object.lambda_package[0].key

  environment {
    variables = {
      ENVIRONMENT      = var.environment
      N8N_CALLBACK_URL = var.n8n_callback_url
      NEXUS_HMAC_SECRET = var.nexus_shared_secret
      VPC_ID           = var.aws_vpc_id
    }
  }

  tags = local.common_tags
}

resource "aws_lambda_function_url" "aws_block_ip" {
  count              = var.enable_aws ? 1 : 0
  function_name      = aws_lambda_function.aws_block_ip[0].function_name
  authorization_type = "AWS_IAM"
}

# ── CloudWatch Log Groups ──────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "isolate" {
  count             = var.enable_aws ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.aws_isolate[0].function_name}"
  retention_in_days = 30
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "block_ip" {
  count             = var.enable_aws ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.aws_block_ip[0].function_name}"
  retention_in_days = 30
  tags              = local.common_tags
}

# ── EventBridge: auto-trigger on GuardDuty HIGH/CRITICAL findings ─────────────
resource "aws_cloudwatch_event_rule" "guardduty_auto_respond" {
  count       = (var.enable_aws && var.guardduty_auto_respond) ? 1 : 0
  name        = "nexus-guardduty-auto-respond-${var.environment}"
  description = "Auto-invoke nexus-aws-isolate on GuardDuty HIGH/CRITICAL findings"
  tags        = local.common_tags

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.guardduty_min_severity] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_lambda" {
  count     = (var.enable_aws && var.guardduty_auto_respond) ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_auto_respond[0].name
  target_id = "nexus-isolate-lambda"
  arn       = aws_lambda_function.aws_isolate[0].arn

  input_transformer {
    input_paths = {
      finding_id   = "$.detail.id"
      severity     = "$.detail.severity"
      type         = "$.detail.type"
      target_ip    = "$.detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4"
      instance_id  = "$.detail.resource.instanceDetails.instanceId"
    }
    input_template = <<-EOT
      {
        "incident_id": "GD-<finding_id>",
        "target_ip":   "<target_ip>",
        "instance_id": "<instance_id>",
        "severity":    "<severity>",
        "finding_type": "<type>",
        "action":      "isolate",
        "source":      "guardduty_auto"
      }
    EOT
  }
}

resource "aws_lambda_permission" "allow_eventbridge_isolate" {
  count         = (var.enable_aws && var.guardduty_auto_respond) ? 1 : 0
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.aws_isolate[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_auto_respond[0].arn
}

# ── SSM Parameters (runtime secrets, referenced by Lambda env vars) ────────────
resource "aws_ssm_parameter" "n8n_callback_url" {
  count = var.enable_aws ? 1 : 0
  name  = "/nexus/containment/n8n_callback_url"
  type  = "SecureString"
  value = var.n8n_callback_url
  tags  = local.common_tags
}

resource "aws_ssm_parameter" "hmac_secret" {
  count = var.enable_aws ? 1 : 0
  name  = "/nexus/containment/hmac_secret"
  type  = "SecureString"
  value = var.nexus_shared_secret
  tags  = local.common_tags
}

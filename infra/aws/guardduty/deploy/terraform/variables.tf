variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "Primary AWS region for centralized logging infrastructure"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Deployment environment tag"
}

variable "project_name" {
  type        = string
  default     = "nexus-guardduty"
  description = "Project name prefix for resource naming"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources"
}

variable "alert_notification_arns" {
  type        = list(string)
  default     = []
  description = "SNS topic ARNs to notify on CloudWatch alarms"
}
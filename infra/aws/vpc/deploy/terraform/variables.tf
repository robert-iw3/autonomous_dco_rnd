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
  default     = "nexus-vpc-telemetry"
  description = "Project name prefix for resource naming"
}
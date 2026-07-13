# ==============================================================================
# Sentinel Nexus -- Cloud Automated Response (Containment) Infrastructure
# Input Variables
# ==============================================================================

# ── Common ─────────────────────────────────────────────────────────────────────
variable "environment" {
  description = "Deployment environment (production / staging)"
  type        = string
  default     = "production"
}

variable "tags" {
  description = "Common tags applied to all cloud resources"
  type        = map(string)
  default = {
    Project   = "sentinel-nexus"
    ManagedBy = "terraform"
    Component = "containment"
  }
}

# ── Feature toggles ────────────────────────────────────────────────────────────
variable "enable_aws"   { type = bool; default = true }
variable "enable_azure" { type = bool; default = false }
variable "enable_gcp"   { type = bool; default = false }

# ── AWS ────────────────────────────────────────────────────────────────────────
variable "aws_region" {
  description = "AWS region where Lambda and EventBridge are deployed"
  type        = string
  default     = "us-east-1"
}

variable "aws_vpc_id" {
  description = "VPC ID to apply Network ACL containment rules to"
  type        = string
  default     = ""
}

variable "aws_nexus_account_id" {
  description = "AWS account ID running Sentinel Nexus (restricts Lambda invocation)"
  type        = string
  default     = ""
}

variable "guardduty_auto_respond" {
  description = "Auto-invoke Lambda on GuardDuty HIGH/CRITICAL findings via EventBridge"
  type        = bool
  default     = true
}

variable "guardduty_min_severity" {
  description = "Minimum GuardDuty severity score to trigger auto-response (0-10)"
  type        = number
  default     = 7.0
}

# ── Azure ──────────────────────────────────────────────────────────────────────
variable "azure_subscription_id" {
  description = "Azure subscription ID for Automation Account deployment"
  type        = string
  default     = ""
}

variable "azure_resource_group" {
  description = "Resource group for Nexus Azure containment resources"
  type        = string
  default     = "nexus-containment-rg"
}

variable "azure_location" {
  description = "Azure region for containment resources"
  type        = string
  default     = "East US"
}

# ── GCP ────────────────────────────────────────────────────────────────────────
variable "gcp_project_id" {
  description = "GCP project ID for Cloud Function deployment"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "GCP region for Cloud Function"
  type        = string
  default     = "us-east1"
}

variable "gcp_network" {
  description = "GCP VPC network name for firewall rule scope"
  type        = string
  default     = "default"
}

# ── n8n integration ────────────────────────────────────────────────────────────
variable "n8n_callback_url" {
  description = "n8n webhook URL that Lambda/Runbook/Function reports results back to"
  type        = string
  default     = "http://n8n:5678/webhook/containment-callback"
  sensitive   = true
}

variable "nexus_shared_secret" {
  description = "Shared secret for authenticating containment callbacks (HMAC)"
  type        = string
  sensitive   = true
  default     = "ChangeMe-SharedSecret-Rotate-In-Production"
}

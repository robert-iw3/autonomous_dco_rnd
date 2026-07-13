# ==============================================================================
# Sentinel Nexus -- Cloud Automated Response Infrastructure
#
# Provisions provider-specific containment automation that worker_soar and n8n
# invoke at runtime when an alert involves a cloud workload.
#
# Architecture per provider:
#
#   AWS   → IAM role + Lambda functions (isolate/block) + EventBridge rule
#           Worker SOAR calls Lambda URL; EventBridge auto-triggers on GuardDuty
#
#   Azure → Automation Account + PowerShell Runbook + Webhook
#           Worker SOAR POSTs to Runbook webhook; runbook modifies NSG rules
#
#   GCP   → Cloud Function (Python) + Service Account + IAM
#           Worker SOAR POSTs to Cloud Function URL; function modifies VPC FW
#
# All endpoints and credentials are written to outputs.tf and consumed by:
#   - operations/infra/containment.toml  (worker_soar routing)
#   - orchestration/rendered/global.env  (n8n environment)
# ==============================================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "azurerm" {
  subscription_id = var.azure_subscription_id
  features {}
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

locals {
  common_tags = merge(var.tags, {
    Environment = var.environment
  })
  # Secret injected as Lambda/Function env var -- rotated via Terraform redeploy
  callback_hmac_key = var.nexus_shared_secret
}

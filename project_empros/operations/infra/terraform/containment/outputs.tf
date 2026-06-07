# ==============================================================================
# Outputs -- consumed by containment.toml generator and global.env template
# ==============================================================================

# -- AWS ------------------------------------------------------------------------
output "aws_isolate_lambda_url" {
  description = "HTTPS URL to invoke the EC2 isolation Lambda (IAM auth required)"
  value       = var.enable_aws ? aws_lambda_function_url.aws_isolate[0].function_url : ""
  sensitive   = false
}

output "aws_block_ip_lambda_url" {
  description = "HTTPS URL to invoke the Network ACL block-IP Lambda (IAM auth required)"
  value       = var.enable_aws ? aws_lambda_function_url.aws_block_ip[0].function_url : ""
  sensitive   = false
}

output "aws_lambda_role_arn" {
  description = "ARN of the Lambda execution role (for cross-account invocation grants)"
  value       = var.enable_aws ? aws_iam_role.lambda_containment[0].arn : ""
}

output "aws_guardduty_rule_arn" {
  description = "ARN of the EventBridge rule auto-triggering Lambda on GuardDuty findings"
  value       = (var.enable_aws && var.guardduty_auto_respond) ? aws_cloudwatch_event_rule.guardduty_auto_respond[0].arn : ""
}

# -- Azure ----------------------------------------------------------------------
output "azure_nsg_runbook_webhook_url" {
  description = "HTTPS webhook URL for the Invoke-NSGIsolation Automation Runbook"
  value       = var.enable_azure ? azurerm_automation_webhook.nsg_isolation[0].uri : ""
  sensitive   = true
}

output "azure_automation_account_name" {
  description = "Name of the Azure Automation Account"
  value       = var.enable_azure ? azurerm_automation_account.nexus[0].name : ""
}

# -- GCP ------------------------------------------------------------------------
output "gcp_isolate_function_url" {
  description = "HTTPS URL of the GCP Cloud Function for VPC firewall isolation"
  value       = var.enable_gcp ? google_cloudfunctions_function.gcp_isolate[0].https_trigger_url : ""
}

output "gcp_service_account_email" {
  description = "Email of the GCP service account used by the Cloud Function"
  value       = var.enable_gcp ? google_service_account.containment[0].email : ""
}

# -- Summary (for containment.toml rendering) ----------------------------------
output "containment_endpoints" {
  description = "Map of provider → endpoint URL for dynamic containment.toml rendering"
  sensitive   = true
  value = {
    aws_isolate_url    = var.enable_aws   ? aws_lambda_function_url.aws_isolate[0].function_url   : ""
    aws_block_ip_url   = var.enable_aws   ? aws_lambda_function_url.aws_block_ip[0].function_url   : ""
    azure_webhook_url  = var.enable_azure ? azurerm_automation_webhook.nsg_isolation[0].uri        : ""
    gcp_function_url   = var.enable_gcp   ? google_cloudfunctions_function.gcp_isolate[0].https_trigger_url : ""
  }
}

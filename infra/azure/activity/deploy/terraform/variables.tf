variable "azure_region" {
  type    = string
  default = "eastus"
}

variable "environment" {
  type    = string
  default = "production"
}

variable "project_name" {
  type    = string
  default = "nexus-activity"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources"
}

variable "alert_action_group_id" {
  type        = string
  default     = ""
  description = "Azure Monitor Action Group ID for alert notifications"
}

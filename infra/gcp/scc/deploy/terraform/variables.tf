variable "gcp_project_id" {
  type = string
}

variable "gcp_organization_id" {
  type = string
}

variable "gcp_region" {
  type    = string
  default = "us-central1"
}

variable "environment" {
  type    = string
  default = "production"
}

# Note: "${project_name}-${environment}-sa" must not exceed 30 characters
# (GCP service account ID limit). With the default "nexus-gcp-scc" +
# "production" the result is 27 characters.
variable "project_name" {
  type    = string
  default = "nexus-gcp-scc"
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Labels applied to all labeled resources for cost allocation and triage"
}

variable "alert_notification_channels" {
  type        = list(string)
  default     = []
  description = "GCP Monitoring notification channel resource IDs for queue-age alerts"
}

# ==============================================================================
# GCP Containment Resources
# ==============================================================================

# ── Service Account for Cloud Function ────────────────────────────────────────
resource "google_service_account" "containment" {
  count        = var.enable_gcp ? 1 : 0
  account_id   = "nexus-containment"
  display_name = "Sentinel Nexus Containment Function"
  project      = var.gcp_project_id
}

resource "google_project_iam_member" "containment_compute_admin" {
  count   = var.enable_gcp ? 1 : 0
  project = var.gcp_project_id
  role    = "roles/compute.securityAdmin"
  member  = "serviceAccount:${google_service_account.containment[0].email}"
}

# ── Cloud Storage bucket for function source ──────────────────────────────────
resource "google_storage_bucket" "function_source" {
  count                       = var.enable_gcp ? 1 : 0
  name                        = "${var.gcp_project_id}-nexus-containment-src"
  location                    = upper(var.gcp_region)
  uniform_bucket_level_access = true
  force_destroy               = true
}

data "archive_file" "gcp_function" {
  count       = var.enable_gcp ? 1 : 0
  type        = "zip"
  source_dir  = "${path.module}/gcp_function"
  output_path = "/tmp/nexus_gcp_containment.zip"
}

resource "google_storage_bucket_object" "function_source" {
  count  = var.enable_gcp ? 1 : 0
  name   = "gcp-containment-${data.archive_file.gcp_function[0].output_md5}.zip"
  bucket = google_storage_bucket.function_source[0].name
  source = data.archive_file.gcp_function[0].output_path
}

# ── Cloud Function: nexus-gcp-isolate ─────────────────────────────────────────
resource "google_cloudfunctions_function" "gcp_isolate" {
  count                 = var.enable_gcp ? 1 : 0
  name                  = "nexus-gcp-isolate-${var.environment}"
  description           = "Sentinel Nexus: block IP via VPC firewall deny rule"
  project               = var.gcp_project_id
  region                = var.gcp_region
  runtime               = "python312"
  available_memory_mb   = 256
  timeout               = 60
  entry_point           = "isolate"
  trigger_http          = true
  service_account_email = google_service_account.containment[0].email

  source_archive_bucket = google_storage_bucket.function_source[0].name
  source_archive_object = google_storage_bucket_object.function_source[0].name

  environment_variables = {
    GCP_PROJECT       = var.gcp_project_id
    GCP_NETWORK       = var.gcp_network
    NEXUS_HMAC_SECRET = var.nexus_shared_secret
    N8N_CALLBACK_URL  = var.n8n_callback_url
    ENVIRONMENT       = var.environment
  }

  labels = {
    environment = var.environment
    managed-by  = "terraform"
    component   = "containment"
  }
}

# ── IAM: allow n8n service account to invoke the function ─────────────────────
resource "google_cloudfunctions_function_iam_member" "invoker" {
  count          = var.enable_gcp ? 1 : 0
  project        = var.gcp_project_id
  region         = var.gcp_region
  cloud_function = google_cloudfunctions_function.gcp_isolate[0].name
  role           = "roles/cloudfunctions.invoker"
  member         = "serviceAccount:${google_service_account.containment[0].email}"
}

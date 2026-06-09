terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }
  }

  backend "azurerm" {}
}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

locals {
  # Key Vault name: 3-24 chars, alphanumerics and hyphens only.
  kv_name = "${substr("${var.project_name}-${var.environment}", 0, 20)}-kv"
}

resource "azurerm_resource_group" "nexus" {
  name     = "${var.project_name}-${var.environment}-rg"
  location = var.azure_region
  tags     = var.tags
}

# --- Event Hub -----------------------------------------------------------

resource "azurerm_eventhub_namespace" "nexus" {
  name                = "${var.project_name}-${var.environment}-ehns"
  location            = azurerm_resource_group.nexus.location
  resource_group_name = azurerm_resource_group.nexus.name
  sku                 = "Standard"
  capacity            = 1
  tags                = var.tags
}

resource "azurerm_eventhub" "nsg_flows" {
  name                = "nsg-flow-events"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  resource_group_name = azurerm_resource_group.nexus.name
  partition_count     = 4
  message_retention   = 7
}

resource "azurerm_eventhub_consumer_group" "nexus_consumer" {
  name                = "nexus-nsg-consumer"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  eventhub_name       = azurerm_eventhub.nsg_flows.name
  resource_group_name = azurerm_resource_group.nexus.name
}

resource "azurerm_eventhub_authorization_rule" "listen" {
  name                = "nexus-listen"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  eventhub_name       = azurerm_eventhub.nsg_flows.name
  resource_group_name = azurerm_resource_group.nexus.name
  listen              = true
  send                = false
  manage              = false
}

# --- Storage (NSG Flow Log destination + Event Grid source) --------------

resource "azurerm_storage_account" "nsg_logs" {
  name                            = replace("${var.project_name}${var.environment}sa", "-", "")
  resource_group_name             = azurerm_resource_group.nexus.name
  location                        = azurerm_resource_group.nexus.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  tags                            = var.tags

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
  }
}

resource "azurerm_storage_container" "nsg_flow_logs" {
  name                  = "insights-logs-networksecuritygroupflowevent"
  storage_account_name  = azurerm_storage_account.nsg_logs.name
  container_access_type = "private"
}

# Event Grid: blob creation → Event Hub
resource "azurerm_eventgrid_system_topic" "storage_events" {
  name                   = "${var.project_name}-blob-events"
  resource_group_name    = azurerm_resource_group.nexus.name
  location               = azurerm_resource_group.nexus.location
  source_arm_resource_id = azurerm_storage_account.nsg_logs.id
  topic_type             = "Microsoft.Storage.StorageAccounts"
  tags                   = var.tags
}

resource "azurerm_eventgrid_system_topic_event_subscription" "blob_to_eventhub" {
  name                = "nsg-blob-to-eventhub"
  system_topic        = azurerm_eventgrid_system_topic.storage_events.name
  resource_group_name = azurerm_resource_group.nexus.name

  eventhub_endpoint_id = azurerm_eventhub.nsg_flows.id

  included_event_types = ["Microsoft.Storage.BlobCreated"]

  subject_filter {
    subject_begins_with = "/blobServices/default/containers/insights-logs-networksecuritygroupflowevent"
  }
}

# --- Table Storage (infrastructure metadata) -----------------------------

resource "azurerm_storage_table" "infra_metadata" {
  name                 = "nexusinfrastructuremetadata"
  storage_account_name = azurerm_storage_account.nsg_logs.name
}

# --- Managed Identity --------------------------------------------------------

resource "azurerm_user_assigned_identity" "connector" {
  name                = "${var.project_name}-${var.environment}-identity"
  location            = azurerm_resource_group.nexus.location
  resource_group_name = azurerm_resource_group.nexus.name
  tags                = var.tags
}

resource "azurerm_role_assignment" "connector_eventhub_receiver" {
  scope                = azurerm_eventhub.nsg_flows.id
  role_definition_name = "Azure Event Hubs Data Receiver"
  principal_id         = azurerm_user_assigned_identity.connector.principal_id
}

# --- Key Vault (secrets storage) ---------------------------------------------

resource "azurerm_key_vault" "connector_secrets" {
  name                       = local.kv_name
  location                   = azurerm_resource_group.nexus.location
  resource_group_name        = azurerm_resource_group.nexus.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 7
  tags                       = var.tags

  public_network_access_enabled = false

  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"
    ip_rules       = []
  }
}

resource "azurerm_role_assignment" "connector_kv_reader" {
  scope                = azurerm_key_vault.connector_secrets.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.connector.principal_id
}

resource "azurerm_key_vault_secret" "auth_token" {
  # checkov:skip=CKV_AZURE_41: auth token is long-lived, rotated via deployment pipeline
  name         = "auth-token"
  value        = "placeholder-set-post-deploy"
  key_vault_id = azurerm_key_vault.connector_secrets.id
  content_type = "text/plain"

  lifecycle {
    ignore_changes = [value]
  }
}

# --- Monitor Alert -----------------------------------------------------------

resource "azurerm_monitor_metric_alert" "eventhub_throttled" {
  name                = "${var.project_name}-${var.environment}-eh-throttled"
  resource_group_name = azurerm_resource_group.nexus.name
  scopes              = [azurerm_eventhub_namespace.nexus.id]
  description         = "Event Hub namespace is being throttled"
  severity            = 2
  tags                = var.tags

  criteria {
    metric_namespace = "Microsoft.EventHub/namespaces"
    metric_name      = "ThrottledRequests"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0
  }

  dynamic "action" {
    for_each = var.alert_action_group_id != "" ? [1] : []
    content {
      action_group_id = var.alert_action_group_id
    }
  }
}

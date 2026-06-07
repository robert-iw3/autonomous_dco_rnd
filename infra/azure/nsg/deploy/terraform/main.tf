terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "nexus" {
  name     = "${var.project_name}-${var.environment}-rg"
  location = var.azure_region
}

# --- Event Hub -----------------------------------------------------------

resource "azurerm_eventhub_namespace" "nexus" {
  name                = "${var.project_name}-${var.environment}-ehns"
  location            = azurerm_resource_group.nexus.location
  resource_group_name = azurerm_resource_group.nexus.name
  sku                 = "Standard"
  capacity            = 1
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
  name                     = replace("${var.project_name}${var.environment}sa", "-", "")
  resource_group_name      = azurerm_resource_group.nexus.name
  location                 = azurerm_resource_group.nexus.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"

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

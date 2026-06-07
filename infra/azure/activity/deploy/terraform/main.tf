terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_subscription" "current" {}

resource "azurerm_resource_group" "nexus" {
  name     = "${var.project_name}-${var.environment}-rg"
  location = var.azure_region
}

resource "azurerm_eventhub_namespace" "nexus" {
  name                = "${var.project_name}-${var.environment}-ehns"
  location            = azurerm_resource_group.nexus.location
  resource_group_name = azurerm_resource_group.nexus.name
  sku                 = "Standard"
  capacity            = 1
}

resource "azurerm_eventhub" "activity_logs" {
  name                = "activity-log-events"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  resource_group_name = azurerm_resource_group.nexus.name
  partition_count     = 4
  message_retention   = 7
}

resource "azurerm_eventhub_consumer_group" "nexus_consumer" {
  name                = "nexus-activity-consumer"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  eventhub_name       = azurerm_eventhub.activity_logs.name
  resource_group_name = azurerm_resource_group.nexus.name
}

resource "azurerm_eventhub_authorization_rule" "listen" {
  name                = "nexus-listen"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  eventhub_name       = azurerm_eventhub.activity_logs.name
  resource_group_name = azurerm_resource_group.nexus.name
  listen              = true
  send                = false
  manage              = false
}

# Send rule for the Diagnostic Setting to write to Event Hub
resource "azurerm_eventhub_authorization_rule" "send" {
  name                = "diagnostic-send"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  eventhub_name       = azurerm_eventhub.activity_logs.name
  resource_group_name = azurerm_resource_group.nexus.name
  listen              = false
  send                = true
  manage              = false
}

# Stream subscription-level Activity Logs to Event Hub
resource "azurerm_monitor_diagnostic_setting" "activity_to_eventhub" {
  name                           = "nexus-activity-stream"
  target_resource_id             = data.azurerm_subscription.current.id
  eventhub_authorization_rule_id = azurerm_eventhub_authorization_rule.send.id
  eventhub_name                  = azurerm_eventhub.activity_logs.name

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
}

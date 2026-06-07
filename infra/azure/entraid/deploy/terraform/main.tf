terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }
  }
}

provider "azurerm" {
  features {}
}

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

resource "azurerm_eventhub" "entraid_logs" {
  name                = "entraid-log-events"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  resource_group_name = azurerm_resource_group.nexus.name
  partition_count     = 4
  message_retention   = 7
}

resource "azurerm_eventhub_consumer_group" "nexus_consumer" {
  name                = "nexus-entraid-consumer"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  eventhub_name       = azurerm_eventhub.entraid_logs.name
  resource_group_name = azurerm_resource_group.nexus.name
}

resource "azurerm_eventhub_authorization_rule" "listen" {
  name                = "nexus-listen"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  eventhub_name       = azurerm_eventhub.entraid_logs.name
  resource_group_name = azurerm_resource_group.nexus.name
  listen              = true
  send                = false
  manage              = false
}

resource "azurerm_eventhub_authorization_rule" "send" {
  name                = "diagnostic-send"
  namespace_name      = azurerm_eventhub_namespace.nexus.name
  eventhub_name       = azurerm_eventhub.entraid_logs.name
  resource_group_name = azurerm_resource_group.nexus.name
  listen              = false
  send                = true
  manage              = false
}

# Entra ID Diagnostic Settings (requires Azure AD Premium P1/P2)
# NOTE: azurerm_monitor_aad_diagnostic_setting streams Entra ID logs
resource "azurerm_monitor_aad_diagnostic_setting" "entraid_to_eventhub" {
  name                           = "nexus-entraid-stream"
  eventhub_authorization_rule_id = azurerm_eventhub_authorization_rule.send.id
  eventhub_name                  = azurerm_eventhub.entraid_logs.name

  enabled_log {
    category = "SignInLogs"
    retention_policy {}
  }
  enabled_log {
    category = "AuditLogs"
    retention_policy {}
  }
  enabled_log {
    category = "NonInteractiveUserSignInLogs"
    retention_policy {}
  }
  enabled_log {
    category = "ServicePrincipalSignInLogs"
    retention_policy {}
  }
  enabled_log {
    category = "RiskyUsers"
    retention_policy {}
  }
}

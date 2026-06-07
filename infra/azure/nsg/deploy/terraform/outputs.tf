output "eventhub_connection_string" {
  value     = azurerm_eventhub_authorization_rule.listen.primary_connection_string
  sensitive = true
}
output "eventhub_name" {
  value = azurerm_eventhub.nsg_flows.name
}
output "storage_account_url" {
  value = azurerm_storage_account.nsg_logs.primary_blob_endpoint
}
output "consumer_group" {
  value = azurerm_eventhub_consumer_group.nexus_consumer.name
}

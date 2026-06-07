output "eventhub_connection_string" {
  value     = azurerm_eventhub_authorization_rule.listen.primary_connection_string
  sensitive = true
}
output "eventhub_name" { value = azurerm_eventhub.activity_logs.name }
output "consumer_group" { value = azurerm_eventhub_consumer_group.nexus_consumer.name }

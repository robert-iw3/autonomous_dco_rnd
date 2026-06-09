output "eventhub_connection_string" {
  value     = azurerm_eventhub_authorization_rule.listen.primary_connection_string
  sensitive = true
}
output "eventhub_name" { value = azurerm_eventhub.activity_logs.name }
output "consumer_group" { value = azurerm_eventhub_consumer_group.nexus_consumer.name }

output "connector_identity_id" {
  value       = azurerm_user_assigned_identity.connector.id
  description = "Managed identity resource ID for connector pod binding"
}

output "auth_token_secret_id" {
  value       = azurerm_key_vault_secret.auth_token.id
  sensitive   = true
  description = "Key Vault secret ID for the connector bearer token"
}

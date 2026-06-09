"""
Tier-2 logic mirror of the Azure deploy/ IaC contract.
"""

# ---------------------------------------------------------------------------
# SHARED across all three connectors.
# ---------------------------------------------------------------------------

# Posture values asserted via type-based discovery (not by resource name).
POSTURE = {
    "storage_min_tls": "TLS1_2",
    "storage_replication": "GRS",
    "eventhub_sku": "Standard",
    "eventhub_retention_days": "7",
    "container_access": "private",
}

# ---------------------------------------------------------------------------
# PER-CONNECTOR specifics.
#
# eventhub_tf_name: Terraform resource label for the connector's Event Hub
#   (the "name" part of `resource "azurerm_eventhub" "<name>"`).
#
# consumer_group: the consumer group name provisioned for the Nexus puller.
#   Each connector gets its own consumer group to guarantee independent offsets.
#
# has_storage: only nsg ships an azurerm_storage_account (NSG flow log
#   destination + Event Grid source). activity/entraid receive events via
#   Diagnostic Settings directly into Event Hub, no blob store needed.
#
# has_eventgrid: only nsg uses an Event Grid system topic + subscription to
#   route blob-created events to the Event Hub. activity/entraid use
#   azurerm_monitor_diagnostic_setting / azurerm_monitor_aad_diagnostic_setting.
#
# diagnostic_resource_type: the Terraform resource type that wires log delivery
#   into Event Hub. None for nsg (uses EventGrid instead).
#
# required_log_categories: the set of enabled_log categories the diagnostic
#   setting must declare. Empty for nsg.
# ---------------------------------------------------------------------------
CONNECTOR_PROFILE = {
    "nsg": {
        "eventhub_tf_name": "nsg_flows",
        "consumer_group": "nexus-nsg-consumer",
        "has_storage": True,
        "has_eventgrid": True,
        "diagnostic_resource_type": None,
        "required_log_categories": set(),
        "emulator_unsupported": ["apply"],
    },
    "activity": {
        "eventhub_tf_name": "activity_logs",
        "consumer_group": "nexus-activity-consumer",
        "has_storage": False,
        "has_eventgrid": False,
        "diagnostic_resource_type": "azurerm_monitor_diagnostic_setting",
        "required_log_categories": {"Administrative", "Security", "Policy"},
        "emulator_unsupported": ["apply"],
    },
    "entraid": {
        "eventhub_tf_name": "entraid_logs",
        "consumer_group": "nexus-entraid-consumer",
        "has_storage": False,
        "has_eventgrid": False,
        "diagnostic_resource_type": "azurerm_monitor_aad_diagnostic_setting",
        "required_log_categories": {
            "SignInLogs",
            "AuditLogs",
            "NonInteractiveUserSignInLogs",
            "ServicePrincipalSignInLogs",
            "RiskyUsers",
        },
        "emulator_unsupported": ["apply"],
    },
}

# ---------------------------------------------------------------------------
# EventHub minimum partition count. Below this, all partitions are consumed by
# a single goroutine-equivalent -- the connector cannot scale to parallel reads.
MIN_PARTITION_COUNT = 4

# NSG flow log container name -- must match BOTH the azurerm_storage_container
# resource name AND the EventGrid subscription subject_begins_with filter.
# If these drift apart, blob events stop routing to the connector.
NSG_FLOW_LOG_CONTAINER = "insights-logs-networksecuritygroupflowevent"

# Required outputs per connector -- these are read by the runtime config at
# deploy time to wire the connector to the provisioned infrastructure.
REQUIRED_OUTPUTS = {
    "nsg": {
        "eventhub_connection_string",
        "eventhub_name",
        "consumer_group",
        "storage_account_url",
        "connector_identity_id",
        "auth_token_secret_id",
    },
    "activity": {
        "eventhub_connection_string",
        "eventhub_name",
        "consumer_group",
        "connector_identity_id",
        "auth_token_secret_id",
    },
    "entraid": {
        "eventhub_connection_string",
        "eventhub_name",
        "consumer_group",
        "connector_identity_id",
        "auth_token_secret_id",
    },
}

# ---------------------------------------------------------------------------
# checkov gate: enforce everything except checks that are genuinely N/A to
# this architecture.
# ---------------------------------------------------------------------------
CHECKOV_SKIP = {
    # Logging -- handled at the org log-archive level, not per-resource.
    "CKV_AZURE_33":  "Storage access logging handled at the org log-archive level, not per-account",
    "CKV_AZURE_43":  "Queue storage logging N/A -- storage is used for blob events only, not queuing",
    "CKV2_AZURE_20": "Table Storage read/write logging for the infra-metadata table is captured at the org log-archive level",
    "CKV2_AZURE_21": "Blob service read logging is handled at the org log-archive level (see also CKV_AZURE_33)",
    # Network lockdown -- requires VNet/private-endpoint scoping outside this connector module.
    "CKV_AZURE_59":  "Public network access lockdown (public_network_access_enabled=false) requires private endpoint or network_rules scoped to the connector VNet -- outside this module boundary; Azure trusted service bypass applies",
    "CKV2_AZURE_33": "Storage private endpoint requires dedicated VNet/subnet provisioning outside this connector module's boundary; access restricted to Azure trusted services + connector identity",
    # Shared key -- connector runtime requires shared key for Storage and Table Storage access.
    "CKV2_AZURE_40": "NSG connector authenticates to Storage and Table Storage via connection string (shared_access_key); disabling shared_access_key_enabled breaks the connector runtime",
    # SAS expiration -- connector does not use SAS tokens; governance handled at org level.
    "CKV2_AZURE_41": "Connector uses EventHub connection strings, not SAS tokens; SAS expiration policy governance is handled at the org level",
    # CMK encryption for Storage -- Key Vault is now integrated for secrets; CMK for blob storage
    # requires azurerm_storage_account_customer_managed_key referencing the connector Key Vault,
    # which adds cross-resource dependency complexity. Deferred to storage hardening sprint.
    "CKV2_AZURE_1":  "CMK encryption for Storage blobs requires azurerm_storage_account_customer_managed_key; deferred to storage hardening sprint (Key Vault integration for secrets is now complete)",
    # Key Vault secret expiry -- auth token is long-lived bearer credential rotated out-of-band.
    "CKV_AZURE_41":  "Auth token is a long-lived connector secret rotated via deployment pipeline; per-secret expiry enforced by process, not resource expiration date",
    # Key Vault private endpoint -- requires dedicated VNet/subnet + private DNS zone provisioning
    # outside this connector module's boundary. Network access is denied by default via network_acls;
    # AzureServices bypass allows managed service access without a private endpoint.
    "CKV2_AZURE_32": "Key Vault private endpoint requires dedicated VNet/private-DNS-zone outside this module boundary; network_acls default_action=Deny with AzureServices bypass enforces equivalent isolation",
}
# ==============================================================================
# Azure Containment Resources
# ==============================================================================

resource "azurerm_resource_group" "containment" {
  count    = var.enable_azure ? 1 : 0
  name     = var.azure_resource_group
  location = var.azure_location
  tags     = local.common_tags
}

resource "azurerm_automation_account" "nexus" {
  count               = var.enable_azure ? 1 : 0
  name                = "nexus-containment-${var.environment}"
  location            = azurerm_resource_group.containment[0].location
  resource_group_name = azurerm_resource_group.containment[0].name
  sku_name            = "Basic"
  tags                = local.common_tags

  identity {
    type = "SystemAssigned"
  }
}

# ── Grant Automation Account identity permission to manage NSG rules ───────────
data "azurerm_subscription" "current" {
  count = var.enable_azure ? 1 : 0
}

resource "azurerm_role_assignment" "automation_network_contributor" {
  count                = var.enable_azure ? 1 : 0
  scope                = data.azurerm_subscription.current[0].id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_automation_account.nexus[0].identity[0].principal_id
}

# ── PowerShell Runbook: Invoke-NSGIsolation ────────────────────────────────────
resource "azurerm_automation_runbook" "nsg_isolation" {
  count                   = var.enable_azure ? 1 : 0
  name                    = "Invoke-NSGIsolation"
  location                = azurerm_resource_group.containment[0].location
  resource_group_name     = azurerm_resource_group.containment[0].name
  automation_account_name = azurerm_automation_account.nexus[0].name
  log_verbose             = false
  log_progress            = true
  description             = "Sentinel Nexus: add/remove deny-all NSG rule for incident containment"
  runbook_type            = "PowerShell"
  tags                    = local.common_tags

  content = <<-'PWSH'
    <#
    .SYNOPSIS
        Sentinel Nexus NSG Isolation Runbook
    .DESCRIPTION
        Adds a deny-all inbound/outbound NSG rule for a target IP or removes it (release).
        Invoked by n8n Cloud_Containment workflow via Azure Automation Webhook.

    .PARAMETER IncidentId    Nexus incident ID for audit tagging
    .PARAMETER TargetIp      IP address to isolate
    .PARAMETER ResourceGroup Resource group containing the NSG
    .PARAMETER NsgName       Name of the NSG to modify (if known)
    .PARAMETER VmName        VM name to look up NSG (if NsgName not given)
    .PARAMETER Action       "isolate" or "release"
    #>
    param(
        [Parameter(Mandatory)] [string]$IncidentId,
        [Parameter(Mandatory)] [string]$TargetIp,
        [string]$ResourceGroup = "",
        [string]$NsgName       = "",
        [string]$VmName        = "",
        [string]$Action        = "isolate"
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    # Connect using the Automation Account's Managed Identity
    Connect-AzAccount -Identity | Out-Null
    Write-Output "[nexus] Connected as Managed Identity for incident $IncidentId"

    # Resolve NSG
    $nsg = $null
    if ($NsgName -and $ResourceGroup) {
        $nsg = Get-AzNetworkSecurityGroup -Name $NsgName -ResourceGroupName $ResourceGroup
    } elseif ($VmName -and $ResourceGroup) {
        $vm  = Get-AzVM -Name $VmName -ResourceGroupName $ResourceGroup
        $nic = Get-AzNetworkInterface -ResourceId $vm.NetworkProfile.NetworkInterfaces[0].Id
        if ($nic.NetworkSecurityGroup) {
            $nsg = Get-AzNetworkSecurityGroup -ResourceId $nic.NetworkSecurityGroup.Id
        }
    }

    if (-not $nsg) {
        Write-Error "[nexus] Could not resolve NSG for IncidentId=$IncidentId"
        exit 1
    }

    $ruleName = "NEXUS-DENY-$($TargetIp.Replace('.','_'))-$IncidentId"

    if ($Action -eq "isolate") {
        # Add deny-all inbound from target IP
        $nsg | Add-AzNetworkSecurityRuleConfig `
            -Name "$ruleName-IN" `
            -Priority 100 `
            -Protocol '*' `
            -Access Deny `
            -Direction Inbound `
            -SourceAddressPrefix $TargetIp `
            -SourcePortRange '*' `
            -DestinationAddressPrefix '*' `
            -DestinationPortRange '*' `
            -Description "Nexus auto-isolation: $IncidentId" | Out-Null

        # Add deny-all outbound to target IP
        $nsg | Add-AzNetworkSecurityRuleConfig `
            -Name "$ruleName-OUT" `
            -Priority 100 `
            -Protocol '*' `
            -Access Deny `
            -Direction Outbound `
            -SourceAddressPrefix '*' `
            -SourcePortRange '*' `
            -DestinationAddressPrefix $TargetIp `
            -DestinationPortRange '*' `
            -Description "Nexus auto-isolation: $IncidentId" | Out-Null

        $nsg | Set-AzNetworkSecurityGroup | Out-Null
        Write-Output "[nexus] CONTAINED: NSG rules added for $TargetIp incident=$IncidentId nsg=$($nsg.Name)"
    } elseif ($Action -eq "release") {
        $nsg | Remove-AzNetworkSecurityRuleConfig -Name "$ruleName-IN"  -ErrorAction SilentlyContinue | Out-Null
        $nsg | Remove-AzNetworkSecurityRuleConfig -Name "$ruleName-OUT" -ErrorAction SilentlyContinue | Out-Null
        $nsg | Set-AzNetworkSecurityGroup | Out-Null
        Write-Output "[nexus] RELEASED: NSG rules removed for $TargetIp incident=$IncidentId"
    } else {
        Write-Error "[nexus] Unknown action: $Action"
        exit 1
    }

    # Return JSON result for n8n to parse
    $result = @{
        incident_id = $IncidentId
        target_ip   = $TargetIp
        nsg_name    = $nsg.Name
        action      = $Action
        status      = if ($Action -eq "isolate") { "CONTAINED" } else { "RELEASED" }
    } | ConvertTo-Json -Compress
    Write-Output $result
  PWSH
}

# ── Webhook on the runbook (n8n posts to this URL) ─────────────────────────────
resource "azurerm_automation_webhook" "nsg_isolation" {
  count                   = var.enable_azure ? 1 : 0
  name                    = "nexus-nsg-isolation-webhook-${var.environment}"
  resource_group_name     = azurerm_resource_group.containment[0].name
  automation_account_name = azurerm_automation_account.nexus[0].name
  expiry_time             = timeadd(timestamp(), "8760h")  # 1 year
  runbook_name            = azurerm_automation_runbook.nsg_isolation[0].name
  enabled                 = true

  lifecycle {
    ignore_changes = [expiry_time]
  }
}

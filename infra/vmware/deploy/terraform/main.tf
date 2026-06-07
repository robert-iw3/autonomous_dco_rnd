terraform {
  required_providers {
    nsxt    = { source = "vmware/nsxt", version = "~> 3.4" }
    vsphere = { source = "hashicorp/vsphere", version = "~> 2.6" }
  }
}

provider "nsxt" {
  host                 = var.nsxt_manager_host
  username             = var.nsxt_username
  password             = var.nsxt_password
  allow_unverified_ssl = false
}

provider "vsphere" {
  vsphere_server       = var.vsphere_server
  user                 = var.vsphere_user
  password             = var.vsphere_password
  allow_unverified_ssl = false
}

# Point NSX-T at the Nexus connector as a remote syslog collector. NSX-T then
# forwards distributed-firewall (DFW) packet logs here. Log level FW_PKTLOG is
# what produces the 5-tuple + verdict lines the connector parses.
resource "nsxt_node_remote_syslog_exporter" "nexus" {
  display_name = "${var.project_name}-${var.environment}-collector"
  server       = var.collector_host
  port         = var.collector_port
  protocol     = upper(var.collector_protocol)
  log_levels   = ["INFO", "WARNING", "ERROR"]
}

# NOTE: vCenter and ESXi syslog targets are host/appliance settings rather than
# first-class Terraform resources. Configure them out-of-band to forward to
# ${var.collector_host}:${var.collector_port}:
#   * vCenter VAMI  -> Syslog Forwarding -> ${var.collector_host}
#   * ESXi advanced -> Syslog.global.logHost = "${var.collector_protocol}://${var.collector_host}:${var.collector_port}"
# vCenter events are expected in CEF; ESXi host logs fall through to the
# generic syslog path in the connector.

terraform {
  required_version = ">= 1.9"
  required_providers {
    nsxt = {
      source  = "vmware/nsxt"
      version = "~> 3.4"
    }
    vsphere = {
      source  = "vmware/vsphere"
      version = "~> 2.6"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
  # State is stored locally by default. Switch to a remote backend for
  # multi-operator or CI/CD workflows (Terraform Cloud, S3-compatible, etc.)
  backend "local" {}
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

# Configure the NSX-T manager syslog exporter via the REST API.
# The vmware/nsxt provider does not expose a first-class Terraform resource
# for node-level syslog exporters; the NSX-T /api/v1/node/services/syslog/exporters
# endpoint is called via local-exec instead.
#
# Log level DEBUG captures DFW packet-level telemetry (5-tuple + verdict lines
# consumed by the connector). INFO/WARNING/ERROR cover management-plane events.
#
# Triggers on any change to the syslog target so the API call re-runs on drift.
resource "null_resource" "nsxt_syslog_exporter" {
  triggers = {
    manager  = var.nsxt_manager_host
    server   = var.collector_host
    port     = var.collector_port
    protocol = upper(var.collector_protocol)
  }

  provisioner "local-exec" {
    environment = {
      NSXT_USER     = var.nsxt_username
      NSXT_PASSWORD = var.nsxt_password
      NSXT_HOST     = var.nsxt_manager_host
      SYSLOG_SERVER = var.collector_host
      SYSLOG_PORT   = var.collector_port
      SYSLOG_PROTO  = upper(var.collector_protocol)
    }
    command = <<-EOT
      curl -sk -u "$NSXT_USER:$NSXT_PASSWORD" \
        -X POST "https://$NSXT_HOST/api/v1/node/services/syslog/exporters" \
        -H "Content-Type: application/json" \
        -d "{\"server\":\"$SYSLOG_SERVER\",\"port\":$SYSLOG_PORT,\"protocol\":\"$SYSLOG_PROTO\",\"log_level\":\"DEBUG\"}"
    EOT
  }
}

# NOTE: vCenter and ESXi syslog targets are host/appliance settings rather than
# first-class Terraform resources. Configure them out-of-band to forward to
# var.collector_host:var.collector_port:
#   * vCenter VAMI  -> Syslog Forwarding -> var.collector_host
#   * ESXi advanced -> Syslog.global.logHost = "<var.collector_protocol>://var.collector_host:var.collector_port"
# vCenter events are expected in CEF; ESXi host logs fall through to the
# generic syslog path in the connector.
#
# The connector runtime requires these environment variables at startup:
#   AUTH_TOKEN        Bearer token for Nexus gateway authentication (required)
#   GATEWAY_URL       Nexus gateway endpoint URL (required)
#   INTEGRITY_SECRET  HMAC-SHA256 key for batch integrity (required)
#   SENSOR_ID         Connector identity (default: vmware-connector-default)
#   SYSLOG_BIND       Listen address (default: 0.0.0.0:1514)

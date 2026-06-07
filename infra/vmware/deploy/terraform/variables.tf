variable "environment"  { type = string; default = "production" }
variable "project_name" { type = string; default = "nexus-vmware" }

# Endpoint of the deployed Nexus VMware connector (this service's syslog ingress).
variable "collector_host" { type = string }
variable "collector_port" { type = number; default = 1514 }
variable "collector_protocol" { type = string; default = "tcp" } # tcp | udp

# NSX-T manager (for distributed firewall log export configuration).
variable "nsxt_manager_host" { type = string }
variable "nsxt_username"     { type = string }
variable "nsxt_password"     { type = string; sensitive = true }

# vCenter (for vCenter/ESXi syslog configuration is typically done on hosts;
# this provider block is included for inventory/management parity).
variable "vsphere_server"   { type = string }
variable "vsphere_user"     { type = string }
variable "vsphere_password" { type = string; sensitive = true }

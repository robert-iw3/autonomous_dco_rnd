variable "environment" {
  type    = string
  default = "production"
}

variable "project_name" {
  type    = string
  default = "nexus-vmware"
}

# Endpoint of the deployed Nexus VMware connector (syslog ingress address).
variable "collector_host" {
  type = string
}

variable "collector_port" {
  type    = number
  default = 1514
}

variable "collector_protocol" {
  type    = string
  default = "tcp"
  # Accepted values: tcp | udp
}

# NSX-T manager (for distributed firewall log export configuration).
variable "nsxt_manager_host" {
  type = string
}

variable "nsxt_username" {
  type      = string
  sensitive = true
}

variable "nsxt_password" {
  type      = string
  sensitive = true
}

# vSphere / vCenter (provider block required for inventory parity;
# syslog targets on ESXi hosts must be set out-of-band via VAMI or
# ESXi advanced configuration).
variable "vsphere_server" {
  type = string
}

variable "vsphere_user" {
  type      = string
  sensitive = true
}

variable "vsphere_password" {
  type      = string
  sensitive = true
}

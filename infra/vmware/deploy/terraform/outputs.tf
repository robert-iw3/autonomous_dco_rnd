output "collector_endpoint" {
  value = "${var.collector_protocol}://${var.collector_host}:${var.collector_port}"
}
output "nsxt_exporter" { value = nsxt_node_remote_syslog_exporter.nexus.display_name }

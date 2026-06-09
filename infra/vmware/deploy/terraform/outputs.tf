output "collector_endpoint" {
  value = "${var.collector_protocol}://${var.collector_host}:${var.collector_port}"
}

output "nsxt_exporter" {
  value = null_resource.nsxt_syslog_exporter.id
}

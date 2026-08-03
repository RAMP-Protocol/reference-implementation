output "worker_script_name" {
  description = "Name of the deployed worker script."
  value       = module.edge.worker_script_name
}

output "worker_route_patterns" {
  description = "Route patterns the worker is bound to."
  value       = module.edge.worker_route_patterns
}

output "worker_hostname_record" {
  description = "Full domain name of the placeholder DNS record, or null when none was created."
  value       = module.edge.worker_hostname_record
}

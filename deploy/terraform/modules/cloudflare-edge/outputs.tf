output "worker_script_name" {
  description = "Name of the deployed worker script."
  value       = cloudflare_workers_script.this.name
}

output "worker_route_patterns" {
  description = "Route patterns the worker is bound to."
  value       = [for route in cloudflare_workers_route.this : route.pattern]
}

output "worker_hostname_record" {
  description = "Full domain name of the placeholder DNS record created for the worker hostname, or null when none was requested."
  value       = var.worker_hostname == null ? null : cloudflare_record.worker_hostname[0].hostname
}

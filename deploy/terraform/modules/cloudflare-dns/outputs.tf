output "record_hostnames" {
  description = "Map of record name to the full domain name Cloudflare created (e.g. exchange => exchange.staging.example.com)."
  value       = { for name, record in cloudflare_record.this : name => record.hostname }
}

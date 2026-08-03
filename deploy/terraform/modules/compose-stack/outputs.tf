output "user_data" {
  description = "Rendered cloud-init user data for the VM module. Contains key material — sensitive."
  value       = local.user_data
  sensitive   = true
}

output "compose_yaml" {
  description = "Rendered docker-compose.yml — the reference bundle an own-DC publisher runs. Contains the database password — sensitive."
  value       = local.compose_yaml
  sensitive   = true
}

output "postgres_password" {
  description = "Generated Postgres password (also embedded in the DSNs inside the compose file)."
  value       = random_password.postgres.result
  sensitive   = true
}

output "zitadel_admin_password" {
  description = "Generated password for the Zitadel console admin (username zadmin). Needed to reach the console at the Zitadel hostname; the identity bootstrap script does not use it — it authenticates with the machine user's PAT."
  value       = random_password.zitadel_admin.result
  sensitive   = true
}

output "vault_root_token" {
  description = "Generated root token of the bundled dev-mode Vault. For operator inspection of custodied agent keys; the Identity Service reads it from its own environment."
  value       = random_password.vault_root_token.result
  sensitive   = true
}

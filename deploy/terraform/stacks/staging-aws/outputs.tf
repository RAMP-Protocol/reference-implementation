output "vm_public_ip" {
  description = "Elastic IP of the staging VM."
  value       = module.vm.public_ip
}

output "ssh_command" {
  description = "SSH command for the operator. Includes -i when ssh_private_key_path is set."
  value = (
    var.ssh_private_key_path == null
    ? module.vm.ssh_command
    : "ssh -i ${var.ssh_private_key_path} ubuntu@${module.vm.public_ip}"
  )
}

output "exchange_url" {
  description = "Public Exchange URL."
  value       = "https://${local.exchange_fqdn}"
}

output "broker_url" {
  description = "Public Broker URL."
  value       = "https://${local.broker_fqdn}"
}

output "identity_url" {
  description = "Public Identity Service URL. Its /mcp path is the endpoint agents point an MCP client at, and its root is where developers sign up."
  value       = "https://${local.identity_fqdn}"
}

output "zitadel_url" {
  description = "Public Zitadel URL (developer sign-in and the admin console)."
  value       = "https://${local.zitadel_fqdn}"
}

output "zitadel_admin_password" {
  description = "Generated password for the Zitadel console admin, username zadmin."
  value       = module.compose_stack.zitadel_admin_password
  sensitive   = true
}

output "publisher_hostname" {
  # Deliberately a bare hostname, unlike the *_url siblings: every consumer
  # wants the host, not a URL — seed-staging.sh inserts it as the tenant
  # domain (tenants.domain is a bare domain by contract) and smoke_staging.py
  # composes per-article URLs from it. Renaming this to a URL would force
  # each of them to strip the scheme back off.
  description = "Demo publisher hostname (bare, no scheme) fronted by the edge worker (null when deploy_edge = false)."
  value       = var.deploy_edge ? local.publisher_fqdn : null
}

output "default_tenant_domain" {
  # The Exchange resolves its default tenant under this exact domain
  # (EXCHANGE_DEFAULT_TENANT), and seed-staging.sh must create the tenant
  # under the same string. Exporting the one derived value lets the seed
  # script read it back instead of deriving its own copy — with two
  # independent derivations, a deploy_edge = false stack seeded the tenant
  # under the client hostname while the Exchange kept looking under
  # demo.<domain>, and every agent Register failed.
  description = "Domain the Exchange resolves its default tenant under; seed-staging.sh creates the tenant under this exact domain."
  value       = local.default_tenant_domain
}

output "origin_url" {
  description = "Demo publisher origin URL an edge worker proxies verified requests to (staging's own worker, or a separately applied stacks/edge)."
  value       = "https://${local.origin_fqdn}"
}

output "ramp_enforce_binding" {
  # smoke.sh reads this back so its bare-fetch expectation follows the
  # deployment: one deployment has exactly one expected outcome, instead of
  # the expectation being configured independently of the stack. Null when
  # deploy_edge = false — the edge posture then belongs to the separately
  # applied stacks/edge.
  description = "Effective agent-key proof-of-possession posture of the deployed edge: \"true\" (the module default) unless ramp_enforce_binding = \"false\" was set. Null when deploy_edge = false."
  value       = var.deploy_edge ? coalesce(var.ramp_enforce_binding, "true") : null
}

output "postgres_password" {
  description = "Generated Postgres password (for the documented one-time seed SQL over SSH)."
  value       = module.compose_stack.postgres_password
  sensitive   = true
}

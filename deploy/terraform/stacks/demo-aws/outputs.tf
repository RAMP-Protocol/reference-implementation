# Output names deliberately match stacks/staging-aws: seed-staging.sh,
# fund-staging-agent.sh, and smoke.sh read outputs through tf_out() and derive
# their key directory from STACK_DIR, so every name and path those scripts
# read exists here under the same meaning.

output "vm_public_ip" {
  description = "Elastic IP of the demo VM."
  value       = module.vm.public_ip
}

output "ssh_command" {
  # No -i here on purpose. Terraform owns the remote endpoint; the operator owns
  # their credential. State is local and gets copied between machines, and
  # terraform output replays a value the last apply stored — so a private-key
  # path baked in here would point at the last applier's workstation and be
  # wrong for everyone else. Select your key locally, with RAMP_SSH_IDENTITY_FILE
  # or an ssh_config Host entry.
  description = "SSH command for the operator. Selects no identity file: your ssh client chooses the key."
  value       = module.vm.ssh_command
}

output "ssh_authorized_keys" {
  description = "The authorized_keys lines rendered for installation, by operator name: who is configured to SSH in, and from where. Public keys only — nothing here is secret."
  value       = module.vm.ssh_authorized_keys
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
  # domain (tenants.domain is a bare domain by contract) and the smoke test
  # composes per-article URLs from it.
  description = "Demo publisher hostname (bare, no scheme) served by CloudFront + Lambda@Edge (null while deploy_edge = false, i.e. during bootstrap)."
  value       = var.deploy_edge ? local.publisher_fqdn : null
}

output "smoke_agent_hostname" {
  # The services verify the smoke agent's signatures by fetching
  # https://<this hostname>/.well-known/http-message-signatures-directory, and
  # the id seeded into ramp.agents must be this exact string. seed-staging.sh
  # and smoke.sh read it back (require_ids_match_stack) to prove the generated
  # agent key's kid matches before signing anything with it.
  description = "Hostname the smoke agent's public key directory is served at — also the smoke agent's identity id (the kid in agent-key.json must equal it)."
  value       = local.smoke_agent_fqdn
}

output "catalog_contributor_hostname" {
  # Same contract as smoke_agent_hostname, for the identity that pushes the
  # demo catalog.
  description = "Hostname the catalog contributor's public key directory is served at — also the contributor's identity id (the kid in contributor-key.json must equal it)."
  value       = local.catalog_contributor_fqdn
}

output "default_tenant_domain" {
  # The Exchange resolves its default tenant under this exact domain
  # (EXCHANGE_DEFAULT_TENANT), and seed-staging.sh must create the tenant
  # under the same string. Exporting the one derived value lets the seed
  # script read it back instead of deriving its own copy.
  description = "Domain the Exchange resolves its default tenant under; seed-staging.sh creates the tenant under this exact domain."
  value       = local.publisher_fqdn
}

output "origin_url" {
  description = "Demo publisher origin URL — the custom origin CloudFront fetches verified content from."
  value       = "https://${local.origin_fqdn}"
}

output "ramp_enforce_binding" {
  # The smoke test reads this back so its bare-fetch expectation follows the
  # deployment. The value reflects what this stack RENDERS into
  # lambda_edge_config; it is true of the running edge only when the deployed
  # zip was built from the current rendered config — changing the variable
  # means re-rendering, rebuilding, and re-applying.
  description = "Agent-key proof-of-possession posture rendered into the Lambda config: \"true\" (the worker default) unless ramp_enforce_binding = \"false\" was set. Null while deploy_edge = false."
  value       = var.deploy_edge ? coalesce(var.ramp_enforce_binding, "true") : null
}

output "postgres_password" {
  description = "Generated Postgres password (for the documented one-time seed SQL over SSH)."
  value       = module.compose_stack.postgres_password
  sensitive   = true
}

# ── AWS-edge specifics (no staging counterpart) ──────────────────────────────

output "lambda_edge_config" {
  # The single source of truth for the baked Lambda config. Write it to a
  # file and feed it to the build script:
  #   terraform output -raw lambda_edge_config > lambda-edge-config.json
  #   ../../scripts/build-lambda-edge.sh lambda-edge-config.json
  # Derived only from variables, so it is available from the very first
  # apply — including the bootstrap apply with deploy_edge = false.
  description = "Per-deployment config JSON for build-lambda-edge.sh — the values baked into the Lambda bundle. Re-render, rebuild, and re-apply after changing any hostname variable or ramp_enforce_binding."
  value       = jsonencode(local.lambda_edge_config)
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution id, for cache invalidations and console lookups (null while deploy_edge = false)."
  value       = var.deploy_edge ? module.edge[0].distribution_id : null
}

output "lambda_qualified_arn" {
  description = "Published (versioned) ARN of the edge function — what CloudFront runs, and the name to search CloudWatch for (as /aws/lambda/us-east-1.<function-name>, in the region that served the request). Null while deploy_edge = false."
  value       = var.deploy_edge ? module.edge[0].lambda_qualified_arn : null
}

# ── Zitadel outbound mail (SES) ──────────────────────────────────────────────
# What the running Zitadel instance was configured with at first boot, so an
# operator can compare it against the provider stored in Zitadel's console
# without reading the state JSON. Changing any of them here does NOT
# reconfigure a running instance — see ses.tf.

output "zitadel_smtp_host" {
  description = "SMTP relay Zitadel was configured to send through, as host:port."
  value       = local.zitadel_smtp_host
}

output "zitadel_smtp_from" {
  description = "Sender address Zitadel sends notification mail as. SES rejects any send whose From differs from this."
  value       = local.zitadel_smtp_from
}

output "zitadel_smtp_username" {
  description = "SMTP username — the IAM access key id of the send-only SES user."
  value       = aws_iam_access_key.zitadel_smtp.id
}

output "zitadel_smtp_password" {
  # sensitive only redacts normal CLI output. The secret access key and this
  # derived password are both stored in plain text in the local state file,
  # and the password is also in the VM's user data — the same posture as every
  # other secret this stack generates.
  description = "SMTP password — the region-derived SES password, not the raw secret access key."
  value       = aws_iam_access_key.zitadel_smtp.ses_smtp_password_v4
  sensitive   = true
}

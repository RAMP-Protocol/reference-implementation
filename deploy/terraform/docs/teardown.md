# Teardown

## Staging (stacks/staging-aws)

```bash
cd deploy/terraform/stacks/staging-aws
terraform destroy
```

Removes, in dependency order: the edge worker + routes + DNS records, the
Elastic IP, the EC2 instance (with all Docker volumes — Postgres, TigerBeetle
ledger, Redis, Zitadel's database and its bootstrap credentials, Caddy
certificates), and the VPC. Nothing persists in AWS or Cloudflare afterwards.

Notes:

- **Agent identities are destroyed, not archived.** The bundled Vault runs in
  dev mode, so the signing keys it custodies live only in that container's
  memory. Destroying takes them with it, and re-applying does not bring them
  back: every developer who had signed up must sign up again, receiving a new
  agent and a new key. Nothing under `keys/` covers this — those are the
  Exchange, Broker, and smoke identities, which are a different set.

- **Certificates**: destroying and re-applying makes Caddy request fresh
  Let's Encrypt certificates. If you cycle often, set `acme_staging = true`
  to avoid production rate limits (5 duplicate certificates per week).
- **Keys**: `keys/` and the local state files are NOT removed by destroy.
  Keep them if you plan to re-apply (same identities); shred them
  (`rm -rf keys/ terraform.tfstate*`) to retire the environment completely.
- **Images**: pushed images stay in the registry; delete them there if
  needed.

## Standalone edge (stacks/edge)

```bash
cd deploy/terraform/stacks/edge
terraform destroy
```

Removes the worker script, its routes, the optional placeholder DNS record,
and the optional WAF skip rule. Content hostnames fall back to whatever DNS
serves without the worker (the placeholder record is removed with it).

## Partial teardown

- Only the edge, keep the VM: `terraform destroy -target=module.edge` in
  staging (or set `deploy_edge = false` and apply).
- Only the VM, keep DNS/edge: not supported — DNS points at the VM's Elastic
  IP, destroy them together.

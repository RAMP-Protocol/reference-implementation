# Variables reference

The authoritative source is each `variables.tf` (every variable carries a
description there). This page is the overview: what you must set, what has a
sensible default, and where secrets go.

Secrets (marked **sensitive**) belong in a gitignored `secrets.auto.tfvars`
or `TF_VAR_*` environment variables — never in committed files.

## stacks/staging-aws

### Required

| Variable | Sensitive | What it is |
|---|---|---|
| `ssh_public_key` | | OpenSSH public key for the VM's `ubuntu` user |
| `ssh_ingress_cidr` | | Your address as a /32 — SSH is closed to everyone else (open ranges like 0.0.0.0/0, and anything wider than /8, are rejected) |
| `cloudflare_api_token` | yes | DNS:Edit + Workers Routes:Edit (zone), Workers Scripts:Edit (account) |
| `cloudflare_account_id` | | Cloudflare account id |
| `cloudflare_zone_id` | | Zone id of `domain` |
| `domain` | | Zone apex the staging hostnames live under |
| `image_prefix` | | Registry path, e.g. `group/project` |
| `acme_email` | | Let's Encrypt registration email |

### Optional

| Variable | Default | Notes |
|---|---|---|
| `aws_region` / `aws_profile` | `us-east-1` / null | Null profile uses your default AWS credentials |
| `name_prefix` | `ramp-staging` | AWS resource naming |
| `instance_type` | `t3.large` | amd64 only — Graviton types are rejected |
| `ssh_private_key_path` | null | Adds `-i <path>` to the `ssh_command` output when the key is not a default one; the key never leaves your machine |
| `image_registry` / `image_tag` | `registry.gitlab.com` / `latest` | Registry switch happens here |
| `registry_username` / `registry_password` | null | Only for private registries; password is **sensitive** |
| `exchange_subdomain` … `publisher_subdomain` | `exchange`, `broker`, `mcp`, `login`, `origin`, `demo` | Hostname labels under `domain`. `mcp` (`identity_subdomain`) also owns a wildcard record: agent directories are published at `<agent-slug>.mcp.<domain>` |
| `billing_adapter` | `tigerbeetle` | Also controls whether the TigerBeetle container runs |
| `acme_staging` | `false` | Untrusted staging CA — use while iterating on apply/destroy |
| `exa_api_key` | null | **Sensitive.** Broker discovery |
| `smoke_agent_subdomain` / `catalog_contributor_subdomain` | `smoke-agent`, `catalog-contributor` | Hostname labels for the smoke identities' public key directories. The full hostname IS each identity's id — `gen-staging-keys.sh` mints the matching kids, and seeding/smoke verify they agree with the stack |
| `resource_owner_id` | `staging-resource-owner` | Settlement payee in the publisher manifest |
| `worker_bundle_path` | in-repo `src/edge/dist/worker.mjs` | Override for out-of-repo bundles |
| `deploy_edge` | `true` | Staging's own edge worker on `demo.<domain>`. Off = backend + demo origin still run in full — the mode for fronting a client hostname with a separately applied `stacks/edge` (see the client-simulation section in deploy-edge-standalone.md) |
| `default_tenant_domain` | null | Domain the Exchange resolves its default tenant under; null = this stack's demo hostname. Set it in the `deploy_edge = false` mode, to the client publisher's hostname — `seed-staging.sh` reads the resolved value back from the stack output |
| `ramp_enforce_binding` | null | Agent-key proof-of-possession on staging's own edge worker (`deploy_edge = true`). Null = enforced, the production posture; `"false"` lets a signed URL be fetched without the bound-key proof. `smoke.sh` reads the posture back from the stack output |
| `create_waf_skip_rule` | `false` | See cloudflare-edge README before enabling |

Key material is not passed as variables — the stack reads
`keys/{ed25519-private.pem,rsa-private.pem,broker-relay-key.json}`
written by `gen-staging-keys.sh` (gitignored). The same script also writes
`agent-key.json` and `contributor-key.json`, which stay local: the smoke check
and the demo ingest sign with them directly. Their PUBLIC halves travel as
`keys/{smoke-agent-wba.json,catalog-contributor-wba.json}` — JWK Set documents
the stack reads at apply time and serves via Caddy at each identity's
hostname, so the services can verify the smoke and ingest signatures.

## stacks/edge

### Required

| Variable | Sensitive | What it is |
|---|---|---|
| `cloudflare_api_token` | yes | Same scopes as above |
| `cloudflare_account_id` / `cloudflare_zone_id` | | Account + zone the worker runs on |
| `exchange_url` | | Exchange base URL |
| `provider_domain` | | Publisher domain in ramp.json |
| `exchanges_json` | | Exchange entries advertised in ramp.json |

### Optional

| Variable | Default | Notes |
|---|---|---|
| `route_patterns` | `["<provider_domain>/*"]` | Set for more (or other) patterns |
| `exchange_wba_url` | `<exchange_url>/.well-known/http-message-signatures-directory` | The path the Web Bot Auth spec fixes |
| `script_name` | `ramp-edge` | Worker name |
| `worker_bundle_path` | in-repo `src/edge/dist/worker.mjs` | Override for out-of-repo bundles |
| `worker_hostname` | null | Creates the proxied placeholder DNS record |
| `origin_url`, `same_zone_origin`, `rsl_body`, `acme_tokens_json`, `catalog_contributors_json`, `ramp_verify_keys`, `ramp_enforce_binding`, `wba_keys_json`, `wba_revocation_url`, `bot_ua_allow_json`, `bot_ua_deny_json` | null | Optional worker bindings — unset means the binding is not created. One of `origin_url` / `same_zone_origin = "true"` is required: the worker refuses to run without an origin mode |
| `create_waf_skip_rule` / `waf_skip_expression` | `false` / null | Zone protections exemption |

## Modules

Module inputs mirror the stack variables above; consult each module's
`variables.tf` (and `modules/cloudflare-edge/README.md`) when composing your
own stack. `modules/compose-stack` additionally exposes `extra_databases`
(multi-exchange topologies), `broker_id`, and `network_subnet` (override the
compose network's default 172.28.0.0/24 when it collides with the host's
existing networks; TigerBeetle takes host 10 of the subnet).

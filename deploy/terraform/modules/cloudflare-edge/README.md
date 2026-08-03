# cloudflare-edge

Deploys the RAMP publisher edge worker to Cloudflare Workers. This is the
**standalone handoff module**: a publisher applies it against
their own Cloudflare account and zone, with no other RAMP infrastructure in the
same Terraform state. `deploy/terraform/stacks/edge` is the ready-made root
configuration for exactly that.

## What it creates

- A worker script from the **pre-built** bundle (`src/edge/dist/worker.mjs`)
- One worker route per entry in `route_patterns`
- Optionally, a proxied placeholder DNS record (`AAAA 100::`) for a
  worker-only hostname
- Optionally, a zone firewall skip rule so WAF / bot heuristics do not block
  agent traffic before the worker runs

The worker environment is delivered as plain-text bindings that mirror the
worker's own config contract (`src/edge/src/config.ts`) one-to-one. The worker
holds no secrets.

## Before you apply: build the bundle

The module uploads a file from disk and never builds it. From the repo root:

```bash
deploy/terraform/scripts/build-cloudflare-edge.sh
# writes src/edge/dist/worker.mjs
```

## Usage

```hcl
module "ramp_edge" {
  source = "../../modules/cloudflare-edge"

  account_id         = var.cloudflare_account_id
  zone_id            = var.cloudflare_zone_id
  worker_bundle_path = "${path.root}/../../../../src/edge/dist/worker.mjs" # from deploy/terraform/stacks/<name>/ up to the repo root

  route_patterns  = ["news.example.com/*"]
  worker_hostname = "news.example.com" # omit if the hostname already has a proxied record

  exchange_url     = "https://exchange.operator.example"
  exchange_wba_url = "https://exchange.operator.example/.well-known/http-message-signatures-directory"
  provider_domain  = "news.example.com"
  exchanges_json = jsonencode([{
    domain             = "exchange.operator.example"
    endpoint           = "https://exchange.operator.example"
    supported_profiles = ["ramp-news-v1"]
  }])

  origin_url = "https://origin.example.com" # omit when the CDN routes to origin itself
}
```

## Inputs

| Name | Required | Meaning |
|---|---|---|
| `account_id` | yes | Cloudflare account that owns the worker |
| `zone_id` | yes | Zone the routes / DNS record live on |
| `worker_bundle_path` | yes | Path to the pre-built `worker.mjs` |
| `route_patterns` | yes | Route patterns, e.g. `["news.example.com/*"]` |
| `exchange_url` | yes | `EXCHANGE_URL` binding |
| `exchange_wba_url` | yes | `EXCHANGE_WBA_URL` binding (WBA directory URL) |
| `provider_domain` | yes | `PROVIDER` binding (publisher domain in ramp.json) |
| `exchanges_json` | yes | `EXCHANGES_JSON` binding (JSON array) |
| `script_name` | no | Worker name (default `ramp-edge`) |
| `worker_hostname` | no | Create a proxied `AAAA 100::` placeholder record |
| `compatibility_date` / `compatibility_flags` | no | Mirror `src/edge/wrangler.toml` |
| `logpush` | no | Workers Trace Events Logpush (default off) |
| `ramp_verify_keys` | no | `RAMP_VERIFY_KEYS` binding |
| `ramp_enforce_binding` | no | `RAMP_ENFORCE_BINDING` binding (`"true"`/`"false"`) |
| `origin_url` | no | `ORIGIN_URL` binding |
| `rsl_body` | no | `RSL_BODY` binding |
| `acme_tokens_json` | no | `ACME_TOKENS_JSON` binding |
| `catalog_contributors_json` | no | `CATALOG_CONTRIBUTORS_JSON` binding |
| `wba_keys_json` | no | `WBA_KEYS_JSON` binding |
| `wba_revocation_url` | no | `WBA_REVOCATION_URL` binding |
| `create_waf_skip_rule` | no | Add a zone firewall skip rule (default off — see below) |
| `waf_skip_expression` | with skip rule | Filter expression for the skip rule |
| `waf_skip_products` | no | Products the skip rule bypasses |

Full descriptions live in `variables.tf`.

## Zone protections (read before production)

Cloudflare zone protections (WAF managed rules, Bot Fight Mode, security
level) run **before** worker routes. Agent traffic presenting signed URLs
looks exactly like the bot traffic those features block, so on a protected
zone you must exempt the worker hostnames. Two options:

- Set `create_waf_skip_rule = true` with a matching `waf_skip_expression` —
  only when the zone does not already have a custom-firewall entrypoint
  ruleset (a zone can hold exactly one; a second one conflicts).
- Add an equivalent skip rule to the zone's existing ruleset, managed
  wherever that ruleset is managed.

Bot Fight Mode (the free-plan toggle) cannot be skipped by ruleset — turn it
off for the zone or upgrade to a plan with configurable bot management.

## Provider version note

Pinned to `cloudflare/cloudflare ~> 4.52`. Provider v5 renamed
`cloudflare_worker_script` → `cloudflare_workers_script` and reshaped
bindings; migrating is confined to `main.tf` of this module.

## Workers Logs

The 4.x provider cannot enable the Workers Logs observability toggle; enable
it per-script in the Cloudflare dashboard (Workers & Pages → your worker →
Settings → Observability). `logpush` here is the separate Trace Events
Logpush feature.

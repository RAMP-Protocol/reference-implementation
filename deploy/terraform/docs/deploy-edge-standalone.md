# Deploying the edge worker standalone (publisher path)

This is the guide for a publisher deploying ONLY the RAMP
edge worker to their own Cloudflare account. Nothing else from this package
is needed, and no other RAMP infrastructure has to exist in your Terraform
state — but the worker does not work alone. It verifies URLs signed by an
Exchange, so the other RAMP components (Exchange, Broker) must be running
somewhere. Usually your Exchange operator runs them and gives you the
values below. If you need to run them yourself, their sources live under
`src/exchange/` and `src/broker/`, and [deploy-staging-aws.md](deploy-staging-aws.md)
in this folder deploys the full stack.

## What the worker does

It runs in front of your content hostname and:

- serves `/.well-known/ramp.json` (your RAMP publisher manifest),
- verifies signed delivery URLs minted by the Exchange and forwards valid
  requests to your origin,
- rejects everything else with the RAMP guidance headers.

It stores no secrets — all configuration is plain text.

## What you need

- Terraform >= 1.8, node + npm (to build the worker bundle once).
- Your Cloudflare **account id** and the **zone id** of the content domain —
  both on the zone Overview page ("API" block).
- An **API token** with: Workers Scripts:Edit (account), Workers Routes:Edit
  and DNS:Edit (the zone). Scope the token to that one account and that one
  zone (Account Resources → your account; Zone Resources → Specific zone),
  not "All accounts" / "All zones" — the token sits in a gitignored file and
  in Terraform state, so keep its blast radius small.
- From your Exchange operator: the Exchange base URL and the values for
  your publisher manifest (see below).

## Steps

```bash
# 1. build the worker bundle (writes src/edge/dist/worker.mjs)
deploy/terraform/scripts/build-cloudflare-edge.sh

# 2. configure
cd deploy/terraform/stacks/edge
cp terraform.tfvars.example terraform.tfvars           # fill in
cp secrets.auto.tfvars.example secrets.auto.tfvars     # the API token
# (or skip the secrets file and export TF_VAR_cloudflare_api_token)

# 3. apply
terraform init
terraform apply
```

## Verify

```bash
curl https://<your-hostname>/.well-known/ramp.json
```

You should see your publisher manifest (your domain + the exchange entries).

## Inputs you will actually set

| Variable | What it is |
|---|---|
| `worker_hostname` | Set to the hostname if it has no DNS record yet; leave out if the hostname already resolves through Cloudflare |
| `exchange_url` | The Exchange base URL (from your Exchange operator) |
| `provider_domain` | Your content domain — the identity in ramp.json |
| `exchanges_json` | The exchange entries advertised in ramp.json (from your Exchange operator) |
| `origin_url` | Where the worker forwards verified requests (your origin) |

Two values are derived for you and only need setting when your setup is
unusual: `route_patterns` defaults to `["<provider_domain>/*"]` (set it for
more or other patterns), and `exchange_wba_url` defaults to
`<exchange_url>/.well-known/http-message-signatures-directory` (the path the
Web Bot Auth spec fixes).

Everything else is optional; the full list with descriptions is in
`deploy/terraform/modules/cloudflare-edge/variables.tf` and the module
README.

## Zone protections — important for production zones

WAF rules, Bot Fight Mode, and similar features run BEFORE the worker.
AI agents fetching signed URLs look like bots to those features, so they must
not act on the worker's hostnames. Options and limits are described in the
module README (`modules/cloudflare-edge/README.md`) — coordinate with
whoever manages the zone's security settings before go-live.

## Updating

- **New worker version**: re-run `build-cloudflare-edge.sh`, then `terraform apply` —
  the worker re-deploys only when the bundle content changed.
- **Config change** (manifest values, routes): edit tfvars, `terraform apply`.

## Deploying on top of the staging stack (client simulation)

This is how WE rehearse the publisher hand-off: the staging stack
(`stacks/staging-aws`) plays the Exchange operator running the RAMP backend, and this stack
plays the client deploying only the edge worker for their own hostname.

1. **Staging side** — deploy (or re-apply) staging with its own worker turned
   off AND the tenant domain pointed at the client hostname, in
   `stacks/staging-aws/terraform.tfvars`:

   ```hcl
   deploy_edge           = false
   default_tenant_domain = "client-news.staging-zone.example"
   ```

   The backend and the demo origin still run in full; only staging's worker,
   its route, and the `demo.<domain>` placeholder record are skipped (on a
   re-apply: destroyed — that hostname stops serving).

   `default_tenant_domain` is required in this mode: it is the domain the
   Exchange resolves its default tenant under (agent Register reads its
   activation policy there), and seed-staging.sh creates the tenant under the
   same value by reading it back from the stack's output. Without it the
   Exchange keeps looking under `demo.<domain>` while the tenant exists under
   the client hostname, and every agent Register fails.

2. **Client side** — fill this stack's `terraform.tfvars` with a hostname of
   your choice on the zone (the "client" hostname) and the staging backend
   as the Exchange operator. With `client-news` on a staging domain `staging-zone.example`:

   ```hcl
   worker_hostname = "client-news.staging-zone.example"
   provider_domain = "client-news.staging-zone.example"
   exchange_url    = "https://exchange.staging-zone.example"
   exchanges_json  = "[{\"domain\":\"exchange.staging-zone.example\",\"endpoint\":\"https://exchange.staging-zone.example\",\"supported_profiles\":[\"ramp-news-v1\"],\"ext\":{\"resource_owner_id\":\"staging-resource-owner\"}}]"
   origin_url      = "https://origin.staging-zone.example"
   ```

   (`route_patterns` and `exchange_wba_url` derive automatically;
   `resource_owner_id` must match staging's `resource_owner_id` tfvar.)
   Then `terraform apply` as usual.

3. **Onboard the client publisher** in the staging Exchange — the same step
   an Exchange operator performs for a real client. The seed script reads the
   publisher hostname from the stack's `default_tenant_domain` output (set in
   step 1), so only the tenant id needs passing:

   ```bash
   TENANT_ID=tenant-client \
   deploy/terraform/scripts/seed-staging.sh
   ```

4. **Verify** — fund the smoke agent if not yet done
   (`deploy/terraform/scripts/fund-staging-agent.sh`), then run the full
   proof against the client hostname:

   ```bash
   PUBLISHER_DOMAIN=client-news.staging-zone.example \
   deploy/terraform/scripts/smoke.sh
   ```

Notes: pick a client hostname that is NOT `demo.<domain>` (staging owns that
name whenever its own worker is on, and two stacks must never manage the same
hostname). Leave `create_waf_skip_rule = false` here if the staging stack
already manages the zone's custom-firewall ruleset — a zone can hold only one.

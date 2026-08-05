# Deploying the AWS demo environment

Step-by-step guide for `stacks/demo-aws`. This stack is the all-AWS sibling of
`stacks/staging-aws`: the same backend VM (Exchange, Broker, Identity Service,
Zitadel, Caddy, demo origin), but DNS lives in **Route 53** and the publisher
hostname is fronted by **CloudFront + Lambda@Edge** running the SAME Ed25519
edge worker the Cloudflare deployments run. No Cloudflare account, zone, or
token is involved anywhere.

The two stacks share their operator scripts and most of their behavior, so
this guide covers what is DIFFERENT and points at
[the staging guide](deploy-staging-aws.md) for everything that is the same.
Commands run from the repository root unless noted.

The operator scripts that read a stack (keys, bootstrap, seed, fund, smoke)
default to the staging one and select the demo stack via `STACK_DIR`. Export
it once per shell, **as an absolute path** — a relative one breaks the
scripts' `terraform -chdir` calls (and exporting `$PWD/deploy/...` from
inside the stack directory doubles the path):

```bash
# from the repository root:
export STACK_DIR="$PWD/deploy/terraform/stacks/demo-aws"
```

## What you need before starting

Same rules as the staging guide: each item says where the value goes, nothing
goes into a `.env` file, AWS credentials stay in `~/.aws`, values go into
`deploy/terraform/stacks/demo-aws/terraform.tfvars` (copied from the example
file next to it), and secrets go into a separate gitignored
`secrets.auto.tfvars` or `TF_VAR_*` environment variables.

- **AWS** — one account, with credentials that can create:
  - EC2, VPC, security group, key pair, and Elastic IP resources (the VM);
  - Lambda, IAM roles/policies, CloudFront, and ACM certificates in
    **us-east-1** (the edge — us-east-1 is a hard Lambda@Edge and CloudFront
    requirement, independent of where the VM runs);
  - record changes in the Route 53 hosted zone below.
  - Verify: `aws sts get-caller-identity`. Goes into: `aws_profile` (only if
    you use a named profile) and `aws_region` (the VM's region — this one is
    your choice).
- **Route 53** — an EXISTING hosted zone for the demo hostnames.
  - The zone's domain goes into: `domain`. The zone id (Route 53 console,
    zone details page) goes into: `route53_zone_id`.
  - The stack only ADDS records to the zone and refuses to overwrite records
    it does not own. If an earlier deployment managed these same names from
    somewhere else, remove those records first with that deployment's own
    tooling — otherwise the first apply fails on the existing records.
- **SSH and your address** — same as the staging guide: `ssh_public_key`,
  `ssh_ingress_cidr` (your `<ip>/32`), and `ssh_private_key_path` when the
  key is not one your ssh client offers by default.
- **Container registry** — same as the staging guide: `image_registry`,
  `image_prefix` (lowercase), `image_tag`, and for private images
  `registry_username` plus `registry_password` in `secrets.auto.tfvars`.
- **TLS certificates** — an email for Let's Encrypt goes into: `acme_email`.
  Caddy on the VM uses it for the service hostnames. The publisher hostname
  is different here: its certificate comes from **ACM** (created by the
  stack in us-east-1, validated automatically over DNS in the same zone) —
  no email, no manual step.
- **EXA API key (optional)** — enables the Broker's EXA-backed discovery.
  Goes into: `exa_api_key` in `secrets.auto.tfvars`. Without it the Broker
  still runs; only that discovery source is off.
- **Local tools**: same list as the staging guide, plus `zip` (the Lambda
  bundle is a zip archive).

There is no catalog-contributor variable: like staging, each smoke identity's
id IS the hostname its public key directory is served at (derived from the
`smoke_agent_subdomain` / `catalog_contributor_subdomain` labels), so the
stack, the key files, and the seed scripts cannot disagree on it.

### Hostname layout — everything under one label

Unlike staging (which spreads `exchange.`, `broker.`, `mcp.` directly under
the domain), the demo nests EVERYTHING under the publisher label so the whole
deployment can live in a shared zone without touching anything else in it:

| Name | Serves |
|------|--------|
| `demo.<domain>` | The publisher — CloudFront + Lambda@Edge |
| `exchange.demo.<domain>` | Exchange (on the VM) |
| `broker.demo.<domain>` | Broker (on the VM) |
| `mcp.demo.<domain>` (+ wildcard `*.mcp.demo`) | Identity Service; the wildcard serves each signed-up agent's key directory |
| `login.demo.<domain>` | Zitadel (developer sign-in) |
| `origin.demo.<domain>` | Demo origin — what CloudFront fetches verified content from |
| `smoke-agent.demo.<domain>` | The smoke agent's public key directory (the hostname IS the agent's identity id) |
| `catalog-contributor.demo.<domain>` | The catalog contributor's public key directory (same contract) |

The labels are variables (`publisher_subdomain` and friends) — override one
only if it collides with a record you already have.

## Step 1 — generate keys

```bash
# STACK_DIR exported above; STAGING_DOMAIN is needed on the FIRST run only
STAGING_DOMAIN=demo.<your domain> deploy/terraform/scripts/gen-staging-keys.sh
```

Writes `deploy/terraform/stacks/demo-aws/keys/` (gitignored). What each key
is for, and why the Broker gets two, is explained in the staging guide's
step 1. Two things differ here: the directory, and the `STAGING_DOMAIN`
value — in this stack every hostname nests under the publisher label, so the
smoke identity hostnames are `smoke-agent.demo.<domain>` and
`catalog-contributor.demo.<domain>`, and the domain they sit directly under
is the PUBLISHER hostname (`demo.<domain>`), not the zone apex. Setting the
zone apex instead mints kids the stack never serves, and seeding fails its
id check until the two key files are deleted and regenerated.

## Step 2 — build and push images

Identical to the staging guide's step 2 (same script, same registry rules,
same registry-switching table). The four images serve both stacks.

## Step 3 — first apply, without the edge

The Lambda bundle cannot exist yet on a fresh checkout, because its
configuration is rendered BY this stack (Lambda@Edge has no environment
variables — the config is baked into the zip, and the stack is the single
source of the hostnames that go into it). So the first apply runs without
the edge:

```bash
cd deploy/terraform/stacks/demo-aws
cp terraform.tfvars.example terraform.tfvars           # fill in
cp secrets.auto.tfvars.example secrets.auto.tfvars     # the secrets
# in terraform.tfvars, uncomment:  deploy_edge = false
terraform init
terraform apply
```

This creates the VM, the Elastic IP, and the Route 53 records for the
service hostnames (including the `*.mcp.demo` wildcard and the two smoke
identity hostnames Caddy serves the key directories at) — everything except
CloudFront, the Lambda, the ACM
certificate, and the `demo.<domain>` record itself (that name stays
unclaimed rather than pointing anywhere wrong).

First-boot behavior on the VM (the Exchange up but rejecting signed requests
until DNS and certificates settle; a crash-looping Identity Service until
step 5) is the same as the staging guide's step 4, including the SSH
commands to watch it.

## Step 4 — render the Lambda config and build the bundle

```bash
# still in deploy/terraform/stacks/demo-aws:
terraform output -raw lambda_edge_config > lambda-edge-config.json
../../scripts/build-lambda-edge.sh lambda-edge-config.json
```

The output is derived only from variables, so it is available right after
step 3's apply. The build bakes the config into
`src/edge/dist/lambda-edge.zip` and smoke-invokes the bundle locally before
zipping — a config the worker rejects fails here, not at the edge.

Re-run BOTH commands (render, then build) after changing any hostname
variable or `ramp_enforce_binding`, then apply again — the running edge only
picks up what is in the zip.

## Step 5 — second apply, with the edge

```bash
# still in deploy/terraform/stacks/demo-aws:
# in terraform.tfvars, remove deploy_edge = false (or set it true)
terraform apply
```

Creates the ACM certificate (DNS-validated in the zone, usually a couple of
minutes), the Lambda@Edge function in us-east-1, the CloudFront
distribution, and the `demo.<domain>` alias record pointing at it.

**Expected waits**: the distribution shows `InProgress` for a few minutes
after every apply that touches it — CloudFront is copying the new
configuration (and the new Lambda version) to its edge locations. The
hostname typically starts answering within 2–5 minutes; a fetch during the
window may still hit the old behavior. This same wait applies to every
LATER apply that changes the edge (new zip, new settings), not just the
first one.

There is no cache to invalidate after content changes: the distribution runs
with caching disabled (correctness first for a demo), so the origin's current
content is what viewers get. If caching is ever enabled on the distribution,
content and behavior changes additionally need
`aws cloudfront create-invalidation --distribution-id $(terraform output -raw cloudfront_distribution_id) --paths "/*"`.

The publisher manifest `/.well-known/ramp.json` is answered by the Lambda
itself as a generated response — it never comes from the origin, so an
origin problem cannot take it down, and it changes only when a new bundle
is deployed. The worker's other discovery routes serve content only when it
is baked into the bundle, and this stack bakes none of it — in particular,
the publisher's own key directory answers 404 (normal here —
agent and exchange keys are published by the Identity Service and the
Exchange, not by the publisher hostname) and `/rsl.txt` answers an empty
200.

## Steps 6–9 — bootstrap, seed, fund, smoke

All four are the staging guide's steps 5–8, run with `STACK_DIR` pointing at
the demo stack (exported at the top of this guide). Everything written there
— the Zitadel bootstrap and its `FORCE=1` semantics, Google sign-in, the
SMTP note, what seeding creates, how test money works, what the smoke check
proves — applies unchanged:

```bash
deploy/terraform/scripts/bootstrap-identity.sh
deploy/terraform/scripts/seed-staging.sh
deploy/terraform/scripts/fund-staging-agent.sh
deploy/terraform/scripts/smoke.sh
```

Two demo-specific notes:

- The Google redirect URI from the staging guide's bootstrap section is
  `https://login.demo.<domain>/ui/login/login/externalidp/callback` here
  (print it with the same `terraform output` one-liner, swapping in this
  stack's directory).
- The smoke check reads the edge's proof-of-possession posture back from
  this stack's `ramp_enforce_binding` output, so its bare-fetch expectation
  follows the deployment automatically. Remember the output describes what
  was RENDERED — if you changed the variable without re-doing step 4, the
  running edge still enforces whatever its zip was built with.

## Verifying by hand

Quick checks anyone can run after the smoke check passes:

- **A person in a browser**: open `https://demo.<domain>/` — the demo
  catalog landing page, with working links to the articles. People browse
  freely; no license involved.
- **An AI crawler**: the same URLs refuse an AI bot and tell it where to
  negotiate:

  ```bash
  curl -si -A "GPTBot/1.0" "https://demo.<domain>/articles/philosophers/thales-of-miletus.txt" | head -12
  ```

  Expect `403`, a JSON body with `"reason": "ai_bot"`, an `X-Content-Rules`
  header pointing at `https://demo.<domain>/.well-known/ramp.json`, and an
  `X-RAMP-Exchange` header naming the Exchange.

### The closing scenario — a real assistant buys the article

This is the demo stakeholders actually watch: an AI assistant, connected to
the deployment over MCP, licenses and fetches a paid article end to end. It
is deliberately manual — it needs a real assistant and a human reading the
answer — so this section is the deliverable; the automated proof stays in
the smoke check.

1. **Connect the assistant.** In an assistant that supports custom MCP
   connectors, add the connector URL:

   ```
   https://mcp.demo.<domain>/mcp
   ```

   The assistant walks you through sign-in: the Identity Service sends you
   to Zitadel (`login.demo.<domain>`), where you sign in with the local
   user the bootstrap created or with Google if you configured it. After
   sign-in the assistant holds a token for an agent whose signing key the
   Identity Service custodies — every tool call below is signed with that
   key on the agent's behalf.

2. **Register and fund the agent.** Ask the assistant to register its agent
   with the exchange (the `ramp_register` tool; `ramp_status` works too if
   it is already registered). The reply carries the agent's `billing_ref` —
   a random handle the Exchange minted. The canary article costs 9.99 EUR
   and a fresh agent's balance is empty, so credit that specific account:

   ```bash
   BILLING_REF=<the handle from the assistant's reply> \
       deploy/terraform/scripts/fund-staging-agent.sh
   ```

   When several people sign up during a session, skip the per-agent step
   and credit every registered agent at once —
   `deploy/terraform/scripts/fund-all-agents.sh` (100 EUR each). Re-running
   the sweep does not credit anyone twice. The sweep and the per-agent
   command above use different labels, so an agent funded by both gets both
   credits — deliberate, and harmless with test money.

3. **Ask for the article by its address.** Discovery is by URL only, so ask
   for the address, not a search:

   > Fetch https://demo.<domain>/articles/philosophers/thales-of-miletus.txt
   > through RAMP and quote what it says.

4. **What success looks like.** The assistant's answer quotes the article,
   including the retrieval-proof markers baked into it — the token
   `RAMP-DEMO-CANARY-8FK3J2-0418` among them (the full marker list is in
   `deploy/fixtures/demo/CATALOG.md`). Those markers exist nowhere but the
   origin file, so quoting them proves the whole loop: discovery through
   the Broker, a licensed purchase from the Exchange, and a delivery the
   edge verified. In the assistant's transcript you can watch the tool
   calls happen: `ramp_discover`, then `ramp_execute`. There is no separate
   fetch step — the Identity Service fetches the content on the agent's
   behalf, signing the delivery request with the custodied key, and returns
   the article body inside the `ramp_execute` result.

5. **What failure looks like, and where to look.**
   - *The assistant quotes a refusal instead of the article*: it fetched
     the URL directly without licensing. The 403 body and headers it saw
     are the negotiation payload from the check above — the fix is asking
     it to use the RAMP tools, not a plain fetch.
   - *A tool call fails*: read the error in the assistant's transcript
     first — the tools return the reason (not signed in, agent not
     registered, insufficient balance, no offer for that URL).
   - *The purchase went through but no article came back*: the
     `ramp_execute` result carries a separate delivery-failure entry with
     the reason, matched to the offer it belongs to — read that first. The
     Lambda's own logs (next section) show the same refusal from the edge's
     side.
   - *Sign-in fails*: the Identity Service and Zitadel logs on the VM
     (`sudo docker compose -f /opt/ramp/docker-compose.yml logs identity zitadel`).

## Where the edge logs are

The Lambda logs land in CloudWatch **in the region that served the
request**, under a log group named `/aws/lambda/us-east-1.<function-name>`
(the deployment region becomes a prefix, and the function name is
`<name_prefix>-edge` — also visible in the `lambda_qualified_arn` output).
A viewer in Europe logs to a European region, not to us-east-1, so search
every region the distribution serves:

```bash
FN=ramp-demo-edge   # <name_prefix>-edge
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  found=$(aws logs describe-log-groups --region "$region" \
      --log-group-name-prefix "/aws/lambda/us-east-1.${FN}" \
      --query 'logGroups[].logGroupName' --output text)
  [ -n "$found" ] && echo "== $region" && \
      aws logs tail "/aws/lambda/us-east-1.${FN}" --region "$region" --since 1h
done
```

An empty result everywhere means no request has reached the function yet
(each serving region creates its group on first use).

## After the first deployment — updating

- **Worker code or edge config changes**: repeat step 4 (render + build),
  then `terraform apply`. The apply publishes a new Lambda version and
  points CloudFront at it; the 2–5 minute propagation wait from step 5
  applies before every edge location runs the new code.
- **Service config and image updates, VM recreates**: exactly the staging
  guide's "updating a running environment" section — including the quick
  image roll over SSH, having to re-run bootstrap, seed, and funding after
  a VM recreate, and clearing the old SSH host key first. The demo's DNS
  and CloudFront pieces are untouched by a VM recreate; the records already
  point at the same Elastic IP.

## Stopping the environment

- **Pause** — stop the EC2 instance, exactly as in the staging guide (swap
  the stack directory in the command). CloudFront and the Lambda cost
  nothing while idle; the publisher hostname answers 502/504 from CloudFront
  while the origin VM is down.
- **Remove** — `terraform destroy` from `stacks/demo-aws`, with one
  Lambda@Edge-specific caveat: **the destroy takes long, and may need a
  second run.** Deleting the CloudFront distribution takes around 20
  minutes (CloudFront disables it at every edge location first). The
  Lambda function cannot be deleted until CloudFront's replicated copies
  drain, which takes from ~30 minutes up to a few hours AFTER the
  distribution is gone — a destroy in that window fails on the function
  with a "replicated function" error. That failure is not damage: wait,
  then run `terraform destroy` again and it finishes cleanly. What is
  removed versus what stays (local keys, state, pushed images) is the same
  as [teardown.md](teardown.md) describes for staging.

**State is a secret** — the "Secrets — read this" section of
[the package README](../README.md) applies to this stack identically: the
local Terraform state embeds the generated passwords and the key material,
so treat `terraform.tfstate*` like a credentials file and back it up
accordingly.

# Deploying the AWS staging environment

Step-by-step guide for `stacks/staging-aws`. Each step says what it does and
what can go wrong. Commands run from the repository root unless noted.

## What you need before starting

Each item says where the value goes. Nothing goes into a `.env` file:
AWS credentials stay in your `~/.aws` config, everything else goes into
`deploy/terraform/stacks/staging-aws/terraform.tfvars` (copied from the 
`deploy/terraform/stacks/staging-aws/terraform.tfvars.example`), and the 
two secrets go into a separate gitignored `secrets.auto.tfvars` — or `TF_VAR_*`
environment variables, if you prefer.

- **AWS**
  - An account with credentials that can create EC2, VPC, security group,
    key pair, and Elastic IP resources. Store the credentials once with
    `aws configure` (or `aws configure --profile <name>`); they live in
    `~/.aws`, never in this repo. If the apply fails with permission
    errors, ask an AWS admin to extend the IAM policy to cover those
    resource types.
  - Verify: `aws sts get-caller-identity` (add `--profile <name>` if you
    use a named profile).
  - Goes into: `aws_profile` (only if you use a named profile — omit it to
    use your default credentials) and `aws_region`.
- **Cloudflare**
  - A zone (domain) for the staging hostnames. Goes into: `domain`.
  - The zone id and account id — both on the zone Overview page ("API" block).
    Go into: `cloudflare_zone_id`, `cloudflare_account_id`.
  - An [API token](https://dash.cloudflare.com/profile/api-tokens) with `DNS:Edit` + `Workers Routes:Edit` on the "_zone_" and
    `Workers Scripts:Edit` on the "_account_". Tighter is better: scope the
    token to your one account and the one staging zone (Account
    Resources → your account; Zone Resources → Specific zone), not
    "All accounts" / "All zones" — this token sits in a gitignored
    file and in Terraform state, so keep its blast radius small.
    Goes into: `cloudflare_api_token` in `secrets.auto.tfvars` —
    never in `terraform.tfvars`.
- **SSH and your address**
  - A keypair (`ssh-keygen -t ed25519` if you have none). The public key 
    (whole key, including the `ssh-ed25519 ...` part)
    goes into: `ssh_public_key`. Terraform installs it on the VM for the
    `ubuntu` user; the matching private key stays on your machine and is
    what lets you in. If that private key is NOT one your ssh client tries
    by default (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, or a key loaded in
    ssh-agent), also set `ssh_private_key_path` — the `ssh_command` output
    then includes `-i <path>` so the command works as printed. Without it
    you would see `Permission denied (publickey)`.
  - Your public IP (`curl ifconfig.me`). Goes into: `ssh_ingress_cidr`
    as `<ip>/32` — SSH is open to that address only.
- **Container registry**
  - A registry the VM can pull from — GitLab Container Registry by
    default. Goes into: `image_prefix` (your `<group>/<project>` path)
    and `image_registry` if not GitLab.
  - If the images are private, the VM needs a pull-only credential: for
    GitLab, a deploy token (Settings → Repository → Deploy tokens) with
    ONLY the `read_registry` scope. Username goes into
    `registry_username`; the password goes into `registry_password` in
    `secrets.auto.tfvars`. Pushing the images from your machine is a
    separate, write-capable credential — see step 2; the VM never gets
    that one.
- **TLS certificates**
  - An email address for Let's Encrypt registration. Goes into:
    `acme_email`.
- **Local tools**: terraform >= 1.8, docker, go, node + npm, python3, uv,
  openssl, curl, ssh.

## Step 1 — generate keys

```bash
deploy/terraform/scripts/gen-staging-keys.sh
```

Writes `deploy/terraform/stacks/staging-aws/keys/` (gitignored):
signing PEMs for the Exchange, keypairs for the Broker relay, the smoke
agent, and the catalog contributor, the Broker's identity key, plus the
shared public-key registry `keys.json`. Re-running never rotates existing
keys.

The Broker gets two keys and they do different jobs. The relay keypair
signs its calls to the Exchange, which verifies them against `keys.json`.
The identity key (`broker-identity-key.pem`, derived once from
`broker-identity-seed`) is the identity the Broker publishes in its own Web
Bot Auth directory, with a 90-day validity window — so it has to survive a
restart, and the Broker refuses to start without it rather than mint a
throwaway that breaks the window it just published. Terraform ships both to
the VM as root-owned key files and no value is ever typed into
`terraform.tfvars`; because they live in your checkout rather than on the
VM, both survive the VM recreates described at the end of this guide.

## Step 2 — build and push images

```bash
# GitLab login: your username + a Personal Access Token with the
# write_registry scope (read_registry recommended alongside). Watch out:
# read_repository does NOT work here — it covers git over HTTPS only, and
# the registry rejects it with "denied: access forbidden".
docker login registry.gitlab.com          # or your registry
# REGISTRY defaults to registry.gitlab.com — a self-hosted registry must be
# passed explicitly
REGISTRY=registry.gitlab.com PREFIX=<group>/<project> deploy/terraform/scripts/build-push-images.sh
```

The push credential stays on your machine — the VM pulls with its own
read-only token (`read_registry` is enough there; see the prerequisites).
`PREFIX` must be lowercase: Docker repository paths reject uppercase, and
GitLab publishes the registry under the lowercased project path.

Builds amd64 images for exchange, broker, identity, and the demo publisher
origin, named `<registry>/<prefix>/<service>:<tag>`.

**Switching registries** (GHCR, Docker Hub, ECR) is always the same three
settings — the image name is built as
`<image_registry>/<image_prefix>/<service>:<image_tag>`:

1. Push with `REGISTRY=<host> PREFIX=<path> scripts/build-push-images.sh`.
2. Set the same two values in `terraform.tfvars`: `image_registry`
   (defaults to `registry.gitlab.com`, so the example file shows it
   commented out) and `image_prefix`.
3. Private images only: `registry_username` in `terraform.tfvars` and
   `registry_password` in `secrets.auto.tfvars`.

Example — GHCR: `REGISTRY=ghcr.io PREFIX=<github-user>/ramp` when pushing,
then `image_registry = "ghcr.io"`, `image_prefix = "<github-user>/ramp"`.
For ECR, create the four repositories first, log in with
`aws ecr get-login-password | docker login ...`, and note ECR passwords
expire after 12 hours — generate a fresh one at apply time
(`TF_VAR_registry_password=$(aws ecr get-login-password) terraform apply`).

## Step 3 — build the edge worker bundle

```bash
deploy/terraform/scripts/build-cloudflare-edge.sh
```

Writes `src/edge/dist/worker.mjs`. Terraform uploads this file as-is.

## Step 4 — configure and apply

```bash
cd deploy/terraform/stacks/staging-aws
cp terraform.tfvars.example terraform.tfvars           # fill in
cp secrets.auto.tfvars.example secrets.auto.tfvars     # the two secrets
terraform init
terraform apply
```

Postgres gets three databases: the shared `ramp` one the Exchange and Broker
split by schema, `identity` for the Identity Service, and `sor` for the
Exchange's System of Record. All three are created once at cluster init — the
services migrate their own schemas but never create their own database, so a
missing one shows up as a crash-looping container, not a helpful error.

What gets created: VPC + EC2 VM + Elastic IP, A records
(`exchange.`, `broker.`, `mcp.`, `login.`, `origin.` under your domain, plus a
wildcard `*.mcp.` for the per-agent directories), and the edge worker on
`demo.<domain>` (all names configurable). The VM boots, installs Docker, writes the Compose bundle and
keys, and starts the stack.

With `deploy_edge = false` only the worker (and the `demo.` hostname) is
skipped — the backend and the demo origin still run in full. Use that mode to
front a client hostname with a separately applied `stacks/edge` instead: see
"Deploying on top of the staging stack" in `deploy-edge-standalone.md`.

Watch out: the word "publisher" appears with two meanings. The `publisher:`
Compose service on the VM is the demo ORIGIN backend (reached via
`origin.<domain>`), while `publisher_subdomain` / the `publisher_hostname`
output name the edge-fronted hostname (`demo.<domain>`) that sits IN FRONT of
that origin. Agents fetch from the second; the first is what the edge worker
proxies verified requests to.

**Expected on first boot**: the Exchange crash-loops for a few minutes until
DNS answers, Caddy has certificates, and the Broker's well-known endpoint is
reachable — it refuses to run without its revocation authority. It settles on
its own (`restart: unless-stopped`).

The Identity Service also crash-loops, and unlike the Exchange it does NOT
settle on its own: it needs the OIDC client that step 5 provisions. That is
expected here, not a failure.

**Let's Encrypt rate limits**: if you apply/destroy repeatedly, set
`acme_staging = true` (untrusted certificates, no rate limits) while
iterating, then flip it off.

Check progress on the VM. The first command runs on your machine (from
`stacks/staging-aws`, where the terraform state is) and logs you into the VM
over SSH; the `docker compose` commands run inside that SSH session, on the VM:

```bash
# on your machine, in deploy/terraform/stacks/staging-aws:
# After a VM recreate, drop the old host key first — the new VM has a new
# identity, so ssh refuses with "REMOTE HOST IDENTIFICATION HAS CHANGED":
ssh-keygen -R "$(terraform output -raw vm_public_ip)"
$(terraform output -raw ssh_command)     # ssh [-i <key>] ubuntu@<vm ip>

# now on the VM:
sudo docker compose -f /opt/ramp/docker-compose.yml ps
sudo docker compose -f /opt/ramp/docker-compose.yml logs -f exchange
```

`Permission denied (publickey)` here means your ssh client did not offer the
private key matching `ssh_public_key` — set `ssh_private_key_path` in
`terraform.tfvars` (see the prerequisites) and re-run
`terraform output -raw ssh_command`; the printed command then carries the
right `-i` flag.

## Step 5 — bootstrap identity

```bash
# Go back at the repository root folder (after step 4 you are in stacks/staging-aws):
deploy/terraform/scripts/bootstrap-identity.sh
```

Provisions the OIDC client the Identity Service signs developers in with, then
starts the service on it. **Until this runs the Identity Service crash-loops**,
because it reads its client id and secret from files that only exist once
Zitadel has been provisioned — expected on a fresh stack, not a failure.

The script waits for Zitadel to answer OIDC discovery over public HTTPS first,
so a fresh apply may sit here for a few minutes while Caddy issues the
certificate. It prints the password of the local sign-in user it creates
(`alice@acme.local`); record it, or reset it later from the Zitadel console.
The console admin is `zadmin`, whose password comes from
`terraform output -raw zitadel_admin_password`.

Re-running is safe — it stops before provisioning when the client already
exists. `FORCE=1` re-provisions, which mints a **new** client secret and
restarts the service onto it.

### Self-registration needs a confirmation email (SMTP)

The login policy this step provisions allows self-registration: the sign-in
page has a "register" option, so a new developer can create an account
without an operator creating it first. Finishing that registration depends
on email, though — Zitadel sends a confirmation code to the new address and
does not treat the account as usable until the code is entered. **The stack
does not configure any SMTP server**, so out of the box that code is never
delivered and a self-registered user gets stuck waiting for it.

Three ways to handle this:

- **Use Google sign-in instead** (next section). A user created through
  Google arrives with the email already marked verified — Google vouches
  for the address — so no confirmation email is needed at all.
- **Verify the user by hand.** Sign in to the Zitadel console as `zadmin`,
  open the user, and mark the email address as verified. Good enough for
  letting individual people in now and then.
- **Configure an SMTP provider** in the Zitadel console: Default settings →
  SMTP provider. Any transactional mail service works (host, user, password,
  sender address). This is the only option that makes self-registration
  fully self-service.

### Optional — Google sign-in

By default developers sign in with the local user this step creates
(`alice@acme.local`). To also offer "Sign in with Google", give the bootstrap
a Google OAuth client — it then registers Google as an external identity
provider in Zitadel and puts the Google button on the sign-in page:

1. **Create the OAuth client in Google Cloud Console**
   ([APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials)):
   "Create credentials" → "OAuth client ID" → application type
   **Web application**. If the Google project has no consent screen yet, the
   console asks you to set one up first — for staging, user type "External"
   in testing mode is enough, with the developers' Google addresses added as
   test users; no Google verification is needed.
2. **Add the authorized redirect URI** to that client. It must be EXACTLY
   Zitadel's callback URL — print it with:

   ```bash
   echo "$(terraform -chdir=deploy/terraform/stacks/staging-aws output -raw zitadel_url)/ui/login/login/externalidp/callback"
   ```

   which is `https://login.<domain>/ui/login/login/externalidp/callback`.
   A wrong or missing URI does not fail here — it fails later, in the
   browser, with Google's `redirect_uri_mismatch` error after clicking the
   button.
3. **Run the bootstrap with both values.** Keep them out of committed files;
   passing them on the command line for the one run is enough:

   ```bash
   GOOGLE_CLIENT_ID=<id> GOOGLE_CLIENT_SECRET=<secret> \
       deploy/terraform/scripts/bootstrap-identity.sh
   ```

Timing matters, because of the re-run guard described above:

- **Fresh stack** (this step not run yet): pass the two variables on the
  normal run, as shown. Everything is provisioned in one go.
- **Already bootstrapped**: a plain re-run stops early ("already
  provisioned") and never reaches the Google part. Add `FORCE=1`:

  ```bash
  FORCE=1 GOOGLE_CLIENT_ID=<id> GOOGLE_CLIENT_SECRET=<secret> \
      deploy/terraform/scripts/bootstrap-identity.sh
  ```

  As noted above, `FORCE=1` also mints a new OIDC client secret for the
  Identity Service. That is fine — the script restarts the service onto the
  new secret itself.
- **Rotating the Google secret later**: the same `FORCE=1` run with the new
  values. The provisioning updates the existing Google entry in place, so
  re-runs never stack a second Google button on the sign-in page.

A Google account is matched to an existing Zitadel user by email address; a
developer signing in with Google for the first time gets a Zitadel user
created automatically. Local sign-in (`alice@acme.local`) keeps working
alongside — Google is an extra option, not a replacement.

## Step 6 — seed

```bash
# from the repository root, like step 5:
deploy/terraform/scripts/seed-staging.sh
```

Registers the demo tenant, the three signing identities, and the Broker's
exchange row, then ingests the demo philosophy feed through the production
ingest binary over public HTTPS. The registration SQL is printed in full
before it runs — it is a documented one-time step over SSH, kept as SQL only
because no registration RPC exists yet (the admin plane covers fee rate and
reporting policy only).

Last, it opens the smoke agent's **billing account** by calling the Register
RPC, signed with the agent's own key, and prints the `billing_ref` it gets
back. That step matters: the SQL above gives the agent an identity, but only
Register mints the `billing_ref`, and that handle is the one thing the Exchange
turns into a ledger account id. Without it a paid request is refused at
authorization with "billing ref required" — before any balance is looked at —
and step 7 would credit an account nothing ever draws from. Re-running is safe:
an agent that is already registered gets the same handle back.

## Step 7 — add test money

```bash
# from the repository root, like step 5:
deploy/terraform/scripts/fund-staging-agent.sh
```

Some demo articles are free, others cost money — the article the smoke check
buys in step 8 costs 9.99 EUR per run. The Exchange keeps money balances in
TigerBeetle (the small accounting database running inside the stack), and a
fresh deployment starts with an empty balance, so without this step the paid
part of the smoke check fails with "insufficient balance".

There is no API for adding money — that is a design decision (ADR-009): a
balance is only ever created by the operator, by hand. This script is that
by-hand step for staging. It prints the exact ledger commands before running
them over SSH, adds 100 EUR (about 10 smoke runs) to the smoke agent's
account, and prints the resulting balance.

The account it credits is the one belonging to the agent's `billing_ref`, the
handle step 6 obtained. The script asks the Exchange for that handle rather
than guessing it, because it is a random string the Exchange chose — nothing
can work it out locally. Strictly it is step 6's *seeding* that has to have
run: the ask is the same registration call step 6 makes, so this script can
open the account itself, but only for an agent the seed has already given an
identity.

Useful settings (all optional):

- `AMOUNT=250` — add a different amount of euros.
- `FUND_LABEL=topup-1` — running the script again with the SAME amount and
  label does nothing (this makes re-runs safe). To add money a second time,
  give the run a new label.
- `BILLING_REF=<handle>` — fund one specific account instead of looking the
  handle up. For recovering a particular account; normally leave it alone.
- Re-run this step after every seed that follows a VM recreate — the ledger
  data lives on the VM and is lost with it. A recreate also empties the
  Exchange's own records, so the agent is given a **new** `billing_ref` and
  therefore a new, empty account. Money credited to the old one is stranded,
  which is harmless in staging but explains why the balance looks lost.

## Step 8 — smoke

```bash
# from the repository root, like steps 6 and 7:
deploy/terraform/scripts/smoke.sh
```

Checks `healthz` on the Exchange, Broker, and Identity Service, checks that
the MCP endpoint answers 401 (mounted, and its bearer gate active — a 200
there would mean anyone could drive the tools that sign with a developer's
custodied key) and that its discovery document is served, checks the edge
worker's ramp.json, then runs the full proof: agent-signed licensed discovery →
relay-execute of the winning offer (the Exchange mints the agent-bound signed
URL) → a fetch WITHOUT proof of possession that the edge must refuse → the
proof-of-possession fetch through the Cloudflare edge → canary marker from
the origin. The proof covers licensing, delivery, and edge enforcement;
billing runs on the TigerBeetle adapter but is not asserted by the smoke
check.

Each run spends 9.99 EUR of the test money added in step 7 (the price of
the article the check buys). If the check starts failing with "insufficient
balance", run step 7 again with a new `FUND_LABEL`.

## Stopping the environment

Two levels, depending on whether you want it back:

- **Pause (keep everything, stop paying for compute)** — stop the EC2
  instance:

  ```bash
  aws ec2 stop-instances --instance-ids \
      $(aws ec2 describe-addresses \
          --public-ips "$(terraform -chdir=deploy/terraform/stacks/staging-aws output -raw vm_public_ip)" \
          --query 'Addresses[0].InstanceId' --output text)
  ```

  (add `--profile <name>` to both aws calls if you use a named profile, or
  just stop it in the AWS console). A stopped instance costs nothing for
  compute; only the disk and the idle Elastic IP keep billing a few dollars
  per month. Start it again with `aws ec2 start-instances` (or the console):
  the Elastic IP stays attached, so DNS keeps working, and the containers
  come back on their own (`restart: unless-stopped`).

- **Remove (delete everything)** — `terraform destroy` from
  `stacks/staging-aws`. See [teardown.md](teardown.md) for what gets
  removed and what stays (local keys, state, pushed images). Nothing is
  lost that a fresh `terraform apply` + bootstrap + seed cannot rebuild in
  minutes, except the agent keys the dev-mode Vault held: those are gone,
  and the developers who owned them have to sign up again.

## After the first deployment — updating a running environment

- **Changing service config** (tfvars, templates): `terraform apply`
  recreates the VM by default (`user_data_replace_on_change`) — data volumes
  are lost, DNS keeps pointing at the same Elastic IP. Re-run the identity
  bootstrap (step 5), seed (step 6), and the test-money step (step 7) after.
  The identity bootstrap is not optional here: the recreate takes Zitadel's
  database with it, so the instance re-initialises empty and the OIDC client
  the Identity Service holds no longer exists. Any agent whose key the
  dev-mode Vault was custodying is gone for good — those developers have to
  sign up again.
  The new VM also has a new SSH host key, so before reconnecting run
  `ssh-keygen -R "$(terraform output -raw vm_public_ip)"`.
  Set `user_data_replace_on_change = false` in the aws-vm module call if you
  prefer hand-managed updates.
- **New image versions**: push with a new tag, change `image_tag`, apply
  (VM recreate), or SSH in and `docker compose pull && up -d` for a quick
  roll without Terraform.
- **Zone protections**: if the Cloudflare zone has WAF/Bot Fight Mode
  enabled, agent fetches through `demo.<domain>` may be blocked before the
  worker runs. See the cloudflare-edge module README; `create_waf_skip_rule`
  exists for zones without a pre-existing custom firewall ruleset.
- **State is a secret** — see the package README.

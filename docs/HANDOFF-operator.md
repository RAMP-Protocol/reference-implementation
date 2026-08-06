# RAMP — Operator Handoff

This document is for the operators who will set up and run the RAMP
components on their own infrastructure. It explains what the platform
is made of, what to prepare before starting, how the network must be
laid out, and where to find the deployment guide for each piece.

## 1. What this is

RAMP is a protocol that lets software agents find, pay for, and
download licensed content from publishers. This repository is a
working implementation of the full path:

```
Agent ── MCP ──► Identity ──► Broker ──► Exchange ──► (signed URL) ──► Edge ──► Origin
```

How a purchase flows:

1. **Ask.** An agent asks for content. It can do this through the
   **Identity** service's MCP tools (`ramp_register`, `ramp_discover`,
   `ramp_execute`, `ramp_report`, `ramp_status`) — Identity then signs
   each call with the agent's stored key — or directly with the
   protocol SDK, signing its own requests with its registered key.
2. **Discover.** The **Broker** finds the exchange that licenses the
   content — it reads the publisher's `ramp.json` file, or falls back
   to the plain URL — and returns the available offers.
3. **Buy.** The agent accepts an offer. The **Exchange** checks the
   signatures, charges the agent's prepaid balance, saves the payment
   record, and returns a signed URL.
4. **Download.** The agent downloads the content from the signed URL.
   The **Edge** checks the URL signature and passes the request on to
   the publisher's own server (the Origin).
5. **Report.** The agent reports its usage to the Exchange that sold
   the content.

## 2. Components

### The four RAMP services

| Service | Path | Built with | What it does |
|---|---|---|---|
| Identity | `src/identity/` | Go | The agent registry. Handles developer sign-up, stores each agent's signing key, and serves the MCP endpoint with the five `ramp_*` tools. It signs every tool call before sending it on. |
| Broker | `src/broker/` | Go | Finds the right exchange for each request and routes the signed request to it. |
| Exchange | `src/exchange/` | Go | Holds the content catalog, creates offers and signed URLs (Ed25519 or CloudFront RSA, chosen per tenant), and records every transaction. |
| Edge | `src/edge/` | TypeScript | Checks signed URLs before content is served. Runs on the CDN — Cloudflare Workers or AWS Lambda@Edge (behind CloudFront) — which is often the publisher's own account rather than your servers. |

### What they need underneath

| Piece | Used by | Notes |
|---|---|---|
| PostgreSQL | Exchange, Broker, Identity | Each service has its own database. One PostgreSQL server can host them all, or each can use a separate one. |
| Redis | Exchange, Broker | Short-lived shared state: the record of already-accepted request signatures (so the same signed request cannot be replayed), and the Broker's per-agent spending counters. A plain managed Redis with default settings is enough. |
| TigerBeetle | Exchange only | The financial ledger: agent balances, reservations, settled charges, publisher revenue. There is no managed TigerBeetle service — check the host requirements before planning anything else. |
| Vault | Identity | Stores the agents' signing keys. |
| Sign-in provider | Identity | Where developers sign in before an agent is created for them. Any standard OIDC provider works — if you already run one, use it. Zitadel is the provider RAMP is tested against, and the one the guides set up. |

The protocol definition lives in a separate published module — see
References at the end of this document.

## 3. Before you start

Every component guide opens with its own list of what it needs. This
section collects those lists in one place, so you can prepare all the
names, certificates, accounts, and hardware before the first
deployment step. The component guides still hold the full detail; the
section numbers below show where to look inside them.

### 3.1 Decisions that are hard to change later

Decide these first. Each one is easy to decide now and hard — or
impossible — to change once the platform is live.

| Decision | Why it must come first |
|---|---|
| The identity zone, e.g. `mcp.example.com` (`IDENTITY_BASE_DOMAIN`) — both Terraform stacks use the `mcp` label | Every agent gets an address inside this zone when it signs up. Changing the zone later breaks every agent that already exists. The built-in default is a development value on a domain you do not own. (`src/identity/CONFIGURATION.md` §3) |
| The sign-in provider's hostname and master key | Zitadel writes its hostname into its own storage at first start, and its master key encrypts everything it stores. Neither can be changed later without losing that data. (`deploy/zitadel/CONFIGURATION.md` §2) |
| Signing scheme for each publisher: Ed25519 or CloudFront RSA | This choice decides which edge setup the publisher needs (Cloudflare worker or CloudFront) and which signing key the Exchange must hold. The Ed25519 key is required at boot; the RSA key only once a CloudFront publisher exists. (`src/exchange/CONFIGURATION.md` §2.2) |
| One shared PostgreSQL database for Exchange and Broker, or separate ones | Both work. The repository's compose files share one. (`deploy/storage/postgres/CONFIGURATION.md` §2.2) |
| How the edge worker reaches the publisher's server | Exactly one of `SAME_ZONE_ORIGIN` (Cloudflare only) or `ORIGIN_URL`. If neither is set, the worker fails on every request. (`src/edge/CONFIGURATION.md` §3.1) |
| The address range your operators connect from | Needed for the Exchange admin listener's allowlist, `ADMIN_ALLOWED_CIDRS`. An empty list denies everyone. (`src/exchange/DEPLOYMENT.md` §7) |

### 3.2 DNS names

The names below use `.example` placeholders — replace them with your
own domain. All the public names need a TLS certificate.

**Public names** (must resolve on the public internet):

| Name | Serves | Notes |
|---|---|---|
| `exchange.example` | Exchange | The Broker, the edge worker, and Identity all fetch its key directory over the public internet. Goes into `EXCHANGE_DOMAIN`. |
| `broker.example` | Broker | The Exchange reads the Broker's `/.well-known/ramp.json` and its revocation list over public HTTPS. Goes into `BROKER_DOMAIN`. |
| `mcp.example.com` | Identity service | Goes into `IDENTITY_AUTH_ISSUER` (as `https://mcp.example.com`). The OAuth redirect address is exactly this plus `/callback`, character for character. In both Terraform stacks this is also the identity zone (`IDENTITY_BASE_DOMAIN`). |
| `*.mcp.example.com` | One subdomain per agent | A wildcard DNS record **and** a matching wildcard certificate. Agents sign up on their own, so you cannot create a DNS record for each one in advance. |
| `login.example` | Sign-in provider (Zitadel) | Developers open it in a browser. |
| `publisher.example` | The publisher's site, with the edge worker in front of it | Usually on the publisher's own CDN account. |

**Internal names** (never public): PostgreSQL, Redis, TigerBeetle,
Vault, and the publisher's origin server (reached only by the edge
worker).

Rules for the identity zone (`src/identity/DEPLOYMENT.md` §8):

- An agent's address is exactly one label under the zone:
  `agent-x.mcp.example.com` works; `a.b.mcp.example.com` does not.
  This matches what a wildcard certificate can cover.
- Whatever proxy or load balancer sits in front must pass the `Host`
  header through unchanged. A proxy that rewrites it makes every
  agent's key page return 404.

Both Terraform guides contain a complete example of these names: the
staging stack
puts each service directly under your domain (identity zone
`mcp.<your domain>`); the demo stack nests everything under the
publisher's label (identity zone `mcp.demo.<your domain>`).

### 3.3 TLS certificates

- One certificate per public name above, plus the wildcard certificate
  for the identity zone. The Terraform stacks obtain them from Let's
  Encrypt automatically (through Caddy), and the CloudFront stack uses
  AWS ACM in the `us-east-1` region.
- The Exchange and the Broker verify request signatures, and the
  signature includes the request scheme (`https`). If either sits behind
  a proxy that accepts HTTPS and forwards plain HTTP — the normal
  setup with Caddy or a load balancer — set
  `RAMP_TRUST_PROXY_HEADERS=true` on that service, and make sure the
  proxy **replaces** the `X-Forwarded-Proto` header rather than adding
  to it (Caddy and AWS ALB do this by default). Never set the flag on
  a service that is reached directly. Without the flag behind such a
  proxy, every signed request fails while the service still reports
  healthy. (`src/exchange/CONFIGURATION.md` §4,
  `src/broker/CONFIGURATION.md` §4)
- PostgreSQL connections must use TLS in production —
  `sslmode=require` at minimum. (`deploy/storage/postgres/CONFIGURATION.md` §2.3)

### 3.4 Accounts and credentials

| What | Details |
|---|---|
| Cloud account | AWS: able to create EC2, VPC, security groups, key pairs, Elastic IPs — and, for the CloudFront path, Lambda, IAM roles, CloudFront, and ACM certificates in `us-east-1`, plus an existing Route 53 zone. Cloudflare: an API token with exactly three permissions — Workers Scripts:Edit (account), Workers Routes:Edit (zone), DNS:Edit (zone) — limited to that one account and one zone, because the token is stored in Terraform state. |
| Container registry | A pull-only token for the registry that hosts the RAMP service images, so your servers can pull them. In the Terraform stacks it goes into `registry_username` and `registry_password`. |
| SSH | For signing in to the virtual machine the Terraform stacks create (the one that runs the Exchange, Broker, and Identity): an ed25519 key pair, plus your own public IP address — the firewall opens port 22 only to that single address (a `/32`). |
| Let's Encrypt | An email address for certificate registration (`acme_email`). |
| Sign-in provider | If you already run an OIDC provider, it must offer: OIDC discovery, the authorization-code flow, a confidential client (with a client secret — not a public browser client), and one exact redirect address. Otherwise deploy Zitadel, which needs its own PostgreSQL database and a 32-character master key from your secret manager. (`deploy/zitadel/DEPLOYMENT.md` §1–2) |
| Vault | A running, unsealed, real Vault server — never a `-dev` one — with a token that has only the permissions the Identity service needs. (`deploy/storage/vault/DEPLOYMENT.md`) |
| Email delivery | Optional only when Google sign-in is turned on — developers then sign in with Google and no email is ever sent. Without Google sign-in, self-sign-up needs a confirmation email, and the staging stack configures no SMTP server: add an SMTP provider in Zitadel, or verify each user by hand in the Zitadel console. |

### 3.5 Host requirements

**TigerBeetle has strict host requirements that some platforms cannot
meet — check them before planning anything else** (`deploy/storage/tigerbeetle/DEPLOYMENT.md`
§1–3):

- Linux kernel 5.6 or newer. The `kernel.io_uring_disabled` setting
  must not be `2` — no container setting can override it; only the
  host's owner can change it.
- The container runtime must grant `--security-opt seccomp=unconfined`
  and `--cap-add IPC_LOCK` — for the TigerBeetle container **and** for
  the Exchange host, because the Exchange embeds the TigerBeetle
  client. If the platform does not allow them, deploy somewhere else —
  no configuration setting can fix it.
- The Exchange image is amd64 only. There is no ARM build.
- The ledger is one file on one disk, on a filesystem that supports
  direct I/O (`ext4` or `xfs`). The deployment guide has a test
  command to check this.
- The replica allocates several times its `--cache-grid` setting. A
  silent exit with code 137 means the value is too large for the
  machine.

Other requirements:

- **PostgreSQL 16** (also tested with PostgreSQL 15.7). The Exchange
  needs **two** databases (catalog and account registry). You create
  them yourself — the services never create databases, and a missing
  one is a boot failure.
- **Redis 7** (also tested with Redis 6), one instance shared by the
  Exchange and every Broker replica, all with the same `REDIS_URL`.
  No persistence, replication, or cluster mode is needed.
- **Synchronized clocks.** Signed requests and signed URLs carry
  expiry times. Keep every host on NTP; if a host's clock is wrong,
  valid requests fail with signature or expiry errors.

## 4. Network layout and ports

### 4.1 Who talks to whom

The four services talk to each other over **public HTTPS, using their
public names** — they do not need a shared private network. Only the
storage connections are private:

```
                    public internet                      private network
  Agents ──► Identity :8083 ──────────────► PostgreSQL, Vault
  Agents ──► Broker   :8082 ──────────────► PostgreSQL, Redis
             Broker ──► Exchange :8081 ───► PostgreSQL (×2), Redis, TigerBeetle
             Edge worker (CDN, port 443) ─► publisher's origin server
```

These calls between the services go over the public internet, so they
must work there: the Exchange reads the Broker's well-known documents;
the Broker and the Exchange fetch agent keys from the identity zone;
the edge worker fetches the Exchange's key directory; and the Identity
service contacts the sign-in provider at start-up — and refuses to
start if it cannot reach it.

### 4.2 Port matrix

| Component | Default port (setting) | Reached by | Protection on that port |
|---|---|---|---|
| Exchange, public | 8081 (`EXCHANGE_ADDR`) | Public internet | Request signatures. Health and well-known routes are open by design. |
| Exchange, admin | 8082 (`ADMIN_ADDR`) | **Operators only** | Source-address allowlist only — there is **no login** on this port. |
| Broker | 8082 (`BROKER_ADDR`) | Public internet | Request signatures. |
| Identity | 8083 (`IDENTITY_ADDR`) | Public internet | OAuth bearer token on `/mcp`; key directories are public by design. |
| Edge worker | 443 on the CDN | Public internet | Verifies signed URLs before serving content. |
| PostgreSQL | 5432 | Services only | Password + TLS. |
| Redis | 6379 | Exchange and Broker only | Password + TLS, both inside `REDIS_URL`. |
| TigerBeetle | 3000 | **Exchange only** | **None.** See the rule below. |
| Vault | 8200 (`VAULT_ADDR`) | Identity service only | Token + TLS. |
| Zitadel | 443 | Public internet | Its own sign-in. |

Watch out: the Exchange's admin port and the Broker's public port both
default to 8082. If both services run on one host with host
networking, change one of them. (`src/exchange/DEPLOYMENT.md` §7)

### 4.3 Three exposure rules

**1. TigerBeetle's port is open by design — the network is its only
protection.** TigerBeetle has no authentication and no TLS; this is
stated in its own manual, not a gap in this integration. Anything that
can reach port 3000 can move money. Keep the ledger on a private
network reachable only from the Exchange, and never publish its port
to the host or a load balancer.
(`deploy/storage/tigerbeetle/CONFIGURATION.md` §2)

**2. The Exchange admin port must never sit behind a proxy.** The
allowlist checks the connection's real source address and deliberately
ignores `X-Forwarded-For` — a proxy or load balancer in front makes
the allowlist useless. Bind it to an internal interface (for example
`127.0.0.1:8082` reached over an SSH tunnel, or a private subnet
address), set `ADMIN_ALLOWED_CIDRS`, and do not publish the port from
the container. This port changes fee rates and reporting policies with
no login. (`src/exchange/DEPLOYMENT.md` §7)

**3. Storage stays private — and still needs credentials.** PostgreSQL,
Redis, and Vault are never reachable from the public internet, and
even inside the private network they run with passwords and TLS. Vault
is the most sensitive store in the platform: whoever can read it can
act as any agent. Treat its access and its backups with the same care
as a certificate authority. (`deploy/storage/vault/CONFIGURATION.md` §1)

**Reference layout.** The staging stack's firewall opens exactly three
ports on the VM: 22 (only from the operator's own `/32`), 80
(certificate issuing and redirect to HTTPS), and 443. Caddy terminates
TLS on 443 and forwards to the services. No storage port and no admin
port is open to the internet.

Two edge rules that fail with no error anywhere when broken
(`src/edge/DEPLOYMENT.md` §6): the worker's routes must cover
`/.well-known/*`, or the documents that tell bots how to buy access
stop being served; and the `workers.dev` hostname must be off and the
DNS record proxied, or requests go around the worker entirely.

### 4.4 Development settings that must never reach production

Every `CONFIGURATION.md` has a section named "development defaults you
must not copy" — that per-component list is the full one. These are
the settings that switch a protection off completely:

- `SKIP_SSRF` and `ALLOW_INSECURE` (Exchange, Broker, Identity):
  leave unset.
- Any `*_WELLKNOWN_SCHEME=http`: keep the `https` default.
- `sslmode=disable` in any database connection string.
- `BROKER_ALLOW_EPHEMERAL_KEY=true`: the Broker's published identity
  would change on every restart.
- `RAMP_BILLING_ADAPTER=inmemory`: balances disappear on every restart
  and no payment is permanently recorded.
- TigerBeetle's `--development` flag: a host crash can lose committed
  transactions. Drop it from both `format` and `start`.
- Vault in `-dev` mode, or its published root token; the published
  `IDENTITY_TOKEN_SIGNING_KEY` example value; the published Zitadel
  master key and passwords in the compose examples.
- Plain `http` addresses between components in edge settings: keys
  fetched over `http` can be changed on the way.

## 5. Deploying

There are two ways to deploy. You can use either one.

### Option A: Terraform stacks (use as a reference)

`deploy/terraform/` contains ready-to-use Terraform setups. Use them to
set up everything at once, or only the edge:

| Stack | Path | Guide | What it sets up |
|---|---|---|---|
| Full staging | `deploy/terraform/stacks/staging-aws/` | `docs/deploy-staging-aws.md` | One AWS virtual machine that runs the whole platform with Docker Compose: Postgres, Redis, TigerBeetle, Exchange, Broker, Identity with its key store and login system, Caddy for TLS, and a demo publisher site. Cloudflare provides DNS and runs the edge worker. |
| Edge only | `deploy/terraform/stacks/edge/` | `docs/deploy-edge-standalone.md` | Only the Cloudflare edge worker. A publisher applies it in their own Cloudflare account. It needs nothing else from this package. |
| AWS demo | `deploy/terraform/stacks/demo-aws/` | `docs/deploy-demo-aws.md` | The same backend virtual machine as staging, but everything runs on AWS: DNS in Route 53, and the publisher site sits behind CloudFront + Lambda@Edge running the same edge worker. No Cloudflare account is needed. |

Start at `deploy/terraform/README.md`. Guide paths are relative to
`deploy/terraform/`. Two more guides, `docs/variables.md` and
`docs/teardown.md`, apply to all stacks.

The staging stack also produces a Docker Compose file. That same file
is the package a publisher receives to run the backend in their own
data center — so staging tests exactly what gets handed over.

### Option B: Deploy each component yourself

Every component can also be deployed on its own, without Terraform.
Each component's directory contains the same three documents:

- `DEPLOYMENT.md` — how to set it up, step by step. Each file ends
  with checks that confirm the deployment works.
- `CONFIGURATION.md` — every setting, with defaults and what they do.
- `RUNBOOK.md` — how to run it day to day.

Deploy the infrastructure first:

1. `deploy/storage/postgres/`
2. `deploy/storage/redis/`
3. `deploy/storage/tigerbeetle/`
4. `deploy/storage/vault/`
5. `deploy/zitadel/` — skip this one if you already run an OIDC
   provider; its guide explains what any provider must offer.

Then the services, in this order:

6. `src/exchange/`
7. `src/broker/`
8. `src/identity/`
9. `src/edge/`

Each `DEPLOYMENT.md` starts with its own list of what it needs, so the
order above is a suggestion, not a hard rule — but it matches how the
guides reference each other.

Three start-up behaviors are normal, not failures:

- **Start the Broker before the Exchange.** The Exchange starts
  without it, but rejects every signed request with `401` until DNS
  resolves and the Broker answers. This fixes itself — no restart is
  needed.
- **The Identity service refuses to start** if it cannot reach the
  sign-in provider. If you restart it while the provider is down, it
  stays down until the provider is back.
- **Vault is not checked at start-up.** With a wrong address or token,
  the Identity service starts, reports healthy, and fails later on
  each request with `503` — so test the Vault connection yourself
  during the deployment checks.

### Checking the whole setup

The checks in each `DEPLOYMENT.md` cover one component at a time (the
last ones also prove its neighbours are reachable). To prove the whole
chain works — an agent discovers content, buys it, downloads it through
the edge, and a download without the agent's key proof is refused —
there is one script: `tests/e2e/smoke_staging.py`.

It is normally run by `deploy/terraform/scripts/smoke.sh`, which only
works against the Terraform stacks from Option A (it reads their
outputs). The script itself, however, is controlled by five environment
variables — the Exchange URL, the Broker URL, the publisher hostname,
the agent id, and the agent's key file — and runs over the public
network, so you can point it at your own deployment. It needs two
things prepared first:

- **An agent that is registered and funded.** Registration is
  something the agent does itself, by calling `Register`. Funding is
  an operator action on the ledger — there is deliberately no API for
  it — and the step-by-step procedure is in
  `deploy/storage/tigerbeetle/RUNBOOK.md` §4.
- **The demo content loaded on the Exchange.** The script looks for a
  specific demo resource — load the demo fixtures, or adapt it to one
  of your own resources.

The variable names and an example invocation are in the script's
opening comment.

## 6. References

- The protocol definition: <https://github.com/RAMP-Protocol/protocol>.
  The Go services consume it as a module, pinned in the root `go.mod`;
  the edge worker consumes the same repository as the npm package
  `@ramp-protocol/sdk-l1`, pinned in `src/edge/package.json`.

# RAMP Identity Service — Deployment Instructions

This document tells you, the DevOps engineer, everything you need to deploy the RAMP
Identity Service on your own infrastructure. You do not need to read the source code.
Follow the steps in order.

Every setting mentioned here is described in full in
[`CONFIGURATION.md`](CONFIGURATION.md). Once the service is running, day-to-day
operation is in [`RUNBOOK.md`](RUNBOOK.md).

Words that may be new are explained the first time they appear.

---

## 1. What the Identity Service is, and where it sits

AI agents do not talk to RAMP directly. They connect to the Identity Service, which
does two things for them.

**It gives each agent an identity.** A developer signs up, and the service gives them
a subdomain of your identity zone — say `agent-ovx4iigs.agents.example` — plus a
private key that it keeps in Vault and never hands out. It publishes the matching
public key at that subdomain, so the Broker and the Exchange can check that a request
really came from that agent.

**It acts on their behalf.** The agent connects to `/mcp` and calls one of five tools
(`ramp_register`, `ramp_status`, `ramp_discover`, `ramp_execute`, `ramp_report`). Each
call is turned into a proper RAMP request, signed with **that agent's** key, and sent
to the Broker or an Exchange. For a purchase, the service goes one step further: it
follows the delivery link the Exchange answered with, fetches the licensed content
from the publisher's delivery edge — proving to that edge that it holds the agent's
key — and returns the content inside the tool result. The key never leaves this
service, so the agent could not make that proof itself.

```
Agent ──► Identity (/mcp) ──► Broker ──► Exchange ──► (signed link) ──► CDN ──► Origin
              │                                                          │
              │      ◄─── fetches the licensed content ──────────────────┘
              │           with the agent's key, and returns
              │           it to the agent
              └── Vault (agent keys) · PostgreSQL · your OIDC provider
```

Two steps that are deliberately kept apart: the agent proves who it is **to this
service** with an access token, and this service proves who the agent is **to the rest
of RAMP** with that agent's key. Neither is ever used in place of the other, and no
tool takes an agent name as an argument, so one agent cannot ask to act as another.

**One dependency to know about before you start.** The service contacts your OIDC
provider when it boots and refuses to start if it cannot reach it. A running service
survives the provider going down — only new sign-ups fail — but a **restart** while it
is down will not come back up. Plan restarts accordingly.

---

## 2. What you need before you start

| What | Where it goes | How to check you have it |
|---|---|---|
| A PostgreSQL database of its own, and a user that owns it | `IDENTITY_DSN` | `psql "$IDENTITY_DSN" -c 'select 1'` |
| A Vault instance with a KV v2 engine and a scoped token | `VAULT_ADDR`, `VAULT_TOKEN`, `IDENTITY_KV_MOUNT` | `vault status` → `Sealed  false` |
| An OIDC provider, and a confidential client registered on it | `IDENTITY_OIDC_*` | `curl -s https://login.example.com/.well-known/openid-configuration` returns JSON |
| A public hostname for this service, with TLS | `IDENTITY_AUTH_ISSUER` | `curl -sI https://id.example.com` returns anything but a DNS error |
| A wildcard DNS record for the identity zone | `IDENTITY_BASE_DOMAIN` | `dig +short anything.agents.example.com` returns your address |
| A wildcard TLS certificate matching that zone | your proxy or load balancer | `openssl s_client -connect anything.agents.example.com:443` shows a `*.agents.example.com` certificate |
| The address of your Broker and your Exchange | `IDENTITY_MCP_*_URL` | Neither has to be answering yet |
| A container runtime | — | `docker version` |
| Python 3 (to generate keys in §7) | — | `python3 --version` |

**Decide the identity zone before anything else.** Every agent this service creates
gets an address inside it, and those addresses are published to other parties and
cached. Changing the zone later leaves every agent already created with an address
that no longer works. If you do not yet know which domain to use, stop here and
decide — the default `rampmcp.org` is a development value and is not yours.

Two of the dependencies above have their own documents, and it is worth reading them
before you set anything up:

- [`deploy/storage/vault/DEPLOYMENT.md`](../../deploy/storage/vault/DEPLOYMENT.md)
- [`deploy/zitadel/DEPLOYMENT.md`](../../deploy/zitadel/DEPLOYMENT.md)

---

## 3. Build or pull the image

The image is published to the GitHub Container Registry. Set the version once —
this is the only place this document names one, and every command below reuses
it:

```bash
VERSION=1.0.0-rc.2
docker pull ghcr.io/ramp-protocol/identity:$VERSION
```

There is no `latest` tag, so the version is never optional. A bare
`docker pull ghcr.io/ramp-protocol/identity` fails rather than fetching something
recent.

In production, deploy the digest rather than the tag. A tag is a pointer, and
whoever holds write access to the registry can move it; a digest names the
content itself and cannot be repointed. Read the digest, then deploy that:

```bash
docker buildx imagetools inspect ghcr.io/ramp-protocol/identity:$VERSION
docker pull ghcr.io/ramp-protocol/identity@sha256:<the digest that printed>
```

To build it yourself instead. The tag is `dev` on purpose: a local build is not
the published artifact, and giving it the release tag invites someone to push it.

```bash
# Run this from the REPOSITORY ROOT, not from src/identity.
# The build needs the shared internal/ directory as well as src/identity/.
docker build -f src/identity/Dockerfile -t ghcr.io/ramp-protocol/identity:dev .
```

Facts about the image:

- **The published image is amd64 only.** No ARM variant is published, so
  `--platform` selects nothing on it. That is a publishing decision, not a limit
  of the code: nothing in this binary is architecture-specific, so you can build
  an ARM image yourself if you need one. On an Apple Silicon laptop the published
  image runs under emulation, which is fine for looking at it and wrong for
  measuring it.
- It is a *distroless* image (no shell, no package manager) and runs as an
  unprivileged user, **uid 65532**. Any secret file you mount must be readable by that
  uid.
- It publishes **port 8083**, matching the `IDENTITY_ADDR` default. If you change
  `IDENTITY_ADDR`, change the published port to match.
- **The image defines no health check of its own**, and there is no shell or `curl`
  inside it to write one with. The binary is its own probe instead: running
  `/identity healthcheck` calls the local `/healthz` and exits with the result, so a
  container health check can exec the service binary itself. Or probe `/healthz`
  from outside.
- **The emergency revocation tool is not in the image.** It is a second binary and
  the image contains only the server. See [`RUNBOOK.md`](RUNBOOK.md) §4.2 — set this
  up before you need it, not during an incident.

---

## 4. Step 1 — create the database

The service needs a database and a user that **owns** it. Create them however you
normally would; nothing else is required.

- **No PostgreSQL extensions are needed.**
- PostgreSQL 16 is the tested version.
- The service creates and uses its own schema called `identity`.

**Give it its own database.** It can share a PostgreSQL cluster with the Exchange and
the Broker — that is expected — but not their database. The account and sign-in
records it holds have a different audience, and a different backup, restore and access
path, from the content catalog. See
[`deploy/storage/postgres/CONFIGURATION.md`](../../deploy/storage/postgres/CONFIGURATION.md) §3.

**You do not run migrations yourself.** The service applies its own database
migrations when it starts, before it begins listening. If a migration fails, it exits
rather than serving traffic on a half-built schema.

Verify you can reach the database as the owning user:

```bash
psql "$IDENTITY_DSN" -c \
  "SELECT current_user, current_database(),
          pg_catalog.pg_get_userbyid(datdba) = current_user AS is_owner
     FROM pg_database WHERE datname = current_database()"
#  current_user | current_database | is_owner
# --------------+------------------+----------
#  ramp         | identity         | t
#
# Expect: one row, is_owner = t
```

The `identity` schema does not exist yet — it is created on first start. Confirming it
was created correctly is Check B in §10.

---

## 5. Step 2 — prepare Vault

Vault holds every agent's private key. It is the most sensitive store in the platform:
whoever can read it can act as any agent in it.

The full procedure — enabling the engine, writing the policy, creating the token, and
what you must back up afterwards — is in
[`deploy/storage/vault/DEPLOYMENT.md`](../../deploy/storage/vault/DEPLOYMENT.md).

You need three values out of it:

| Value | Variable |
|---|---|
| Vault's address | `VAULT_ADDR` |
| A token limited to the agent-key paths | `VAULT_TOKEN` |
| The engine path you enabled | `IDENTITY_KV_MOUNT` |

> **Do not give this service a root token.** It needs four operations on one path
> prefix and nothing else. The exact policy is in that document.

---

## 6. Step 3 — register the service with your OIDC provider

Developers sign in through your existing identity provider; this service never holds
their password. It needs a **confidential client** registered there — one that
authenticates with a client secret, not a public browser client.

The full procedure, using Zitadel, is in
[`deploy/zitadel/DEPLOYMENT.md`](../../deploy/zitadel/DEPLOYMENT.md). Any provider that
supports OIDC discovery and the authorization-code flow works; the requirements are in
that document's §1.

Whatever you use, the client must have this redirect address on file, exactly:

```
https://id.example/callback
```

That is `IDENTITY_AUTH_ISSUER` with `/callback` appended, and it must match
character for character. A trailing slash, `http` instead of `https`, or a different
hostname all produce the same failure: sign-in stops at the provider with a
redirect-URI error, and nothing appears in this service's logs at all.

You need four values out of this step:

| Value | Variable |
|---|---|
| The provider's address | `IDENTITY_OIDC_ISSUER` |
| The client id | `IDENTITY_OIDC_CLIENT_ID` or `..._FILE` |
| The client secret | `IDENTITY_OIDC_CLIENT_SECRET` or `..._FILE` |
| This service's own public address | `IDENTITY_AUTH_ISSUER` |

Verify the provider answers before you go on:

```bash
curl -s https://login.example/.well-known/openid-configuration | head -c 200
# Expect: JSON whose "issuer" is exactly the value you will set as
#         IDENTITY_OIDC_ISSUER — if it differs, use the one reported here
```

---

## 7. Step 4 — generate the two service keys

These are the service's own keys, separate from the per-agent keys Vault holds. Both
are 32 random bytes in **standard** base64 — 44 characters, ending in `=`.

```bash
python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
# Expect: a 44-character string ending in "=", for example
# LUyYCxS8RrANHtnVf6kPGnxficIti/1eNSkK5q6aY5w=
```

Run it twice. Store one as `IDENTITY_SESSION_KEY` and the other as
`IDENTITY_TOKEN_SIGNING_KEY` in your secret manager.

> **This is a different format from the Broker's `BROKER_ED25519_SEED`**, which is
> URL-safe and 43 characters with no padding. Do not reuse a value or a command
> between the two.

Neither key stops the service starting, which is exactly why they are easy to forget:

| Left unset | What happens |
|---|---|
| `IDENTITY_SESSION_KEY` | A new one every restart. Sign-ups that were halfway through fail; nothing else. |
| `IDENTITY_TOKEN_SIGNING_KEY` | A new one every restart. **Every access token ever issued stops working**, so every agent is signed out at the moment of the restart, with nothing in the logs connecting the two. |

Both cases log one `WARN` at start-up ([`CONFIGURATION.md`](CONFIGURATION.md) §2).
Check for them in §10.

---

## 8. Step 5 — publish the identity zone

Point the wildcard at whatever sits in front of this service, and make sure the
certificate covers it.

```bash
dig +short anything.agents.example
# Expect: the address of your load balancer or proxy. Any name under the zone
# must resolve — agents are created by developers, so you never get to add a
# record per agent.

openssl s_client -connect anything.agents.example:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
# Expect: DNS:*.agents.example
```

Whatever terminates TLS must **pass the `Host` header through unchanged**. The service
works out which agent is being asked about from that header alone; a proxy that
rewrites it makes every agent's documents return `404`.

Unlike the Exchange and the Broker, this service is happy behind a proxy that
terminates HTTPS — [`CONFIGURATION.md`](CONFIGURATION.md) §5 explains why the rule
differs here.

---

## 9. Step 6 — run it

Give the container the environment from [`CONFIGURATION.md`](CONFIGURATION.md) §7. A
minimal Docker Compose service:

```yaml
services:
  identity:
    # A digest, not a tag — §3 explains why production pins the content itself.
    image: ghcr.io/ramp-protocol/identity@sha256:<the digest from §3>
    restart: unless-stopped
    ports:
      - "8083:8083"
    environment:
      IDENTITY_DSN: "postgres://ramp:${DB_PASSWORD}@db.internal:5432/identity?sslmode=require"
      IDENTITY_ADDR: ":8083"
      IDENTITY_BASE_DOMAIN: "agents.example"
      IDENTITY_AUTH_ISSUER: "https://id.example"
      IDENTITY_OIDC_ISSUER: "https://login.example"
      IDENTITY_OIDC_CLIENT_ID_FILE: "/secrets/oidc_client_id"
      IDENTITY_OIDC_CLIENT_SECRET_FILE: "/secrets/oidc_client_secret"
      IDENTITY_SESSION_KEY: "${IDENTITY_SESSION_KEY}"
      IDENTITY_TOKEN_SIGNING_KEY: "${IDENTITY_TOKEN_SIGNING_KEY}"
      IDENTITY_MCP_BROKER_URL: "https://broker.example"
      IDENTITY_MCP_EXCHANGE_URL: "https://exchange.example"
      VAULT_ADDR: "https://vault.internal:8200"
      VAULT_TOKEN: "${VAULT_TOKEN}"
      IDENTITY_KV_MOUNT: "ramp-agents"
    volumes:
      - ./secrets:/secrets:ro
```

Start it, then confirm it came up cleanly:

```bash
docker compose logs identity
# Expect exactly these two lines:
#   {"level":"INFO","msg":"migrations applied","version":4,"dirty":false,"table":"schema_migrations_identity"}
#   {"level":"INFO","msg":"identity listening","addr":":8083"}
#
# Any identity.signup.ephemeral_* WARN line means §7 was not completed.
```

If it exited instead, the `identity.exit` line names the cause:

| `err` begins with | Cause |
|---|---|
| `IDENTITY_DSN is required` | The variable is unset. |
| `db setup:` | The database is unreachable, or a migration failed. |
| `sign-up config: developer sign-up requires` | One of the four OIDC values is missing. |
| `sign-up config: oidc upstream: oidcup: discover` | The OIDC provider did not answer. Check the address and that it is reachable from this container. |
| `sign-up config: IDENTITY_SESSION_KEY must decode to` | The key is not 32 bytes of standard base64 (§7). |
| `keystore:` | The Vault client could not be built — usually a `VAULT_ADDR` that is not a valid address at all. |
| `mcp config: both IDENTITY_MCP_` | One or both peer addresses are missing. |
| `mcp config: IDENTITY_MCP_MAX_` | One of the two content byte caps is not a positive whole number. |
| `build server:` | The server could not be assembled from the settings — for example a per-item content cap larger than the per-call cap. The rest of the message names the exact cause. |

Note that a **wrong-but-well-formed Vault address is not on that list** — only a
`VAULT_ADDR` the client cannot even parse stops start-up (the `keystore:` row). An
address that parses but points nowhere, a missing token, or a sealed Vault all let
the service start normally. Check C in §10 is what catches those.

---

## 10. Step 7 — verify the deployment

Five checks. Run them in order; each one builds on the last.

**Check A — the service is alive.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://id.example/healthz
# Expect: 200
```

Note this checks the database connection **only**. It stays green with Vault
unreachable and with your OIDC provider down — see [`RUNBOOK.md`](RUNBOOK.md) §2.1.

**Check B — the schema was created.**

```bash
psql "$IDENTITY_DSN" -c \
  "SELECT table_schema AS schema, count(*) AS tables
     FROM information_schema.tables
    WHERE table_schema NOT IN ('pg_catalog','information_schema')
    GROUP BY 1 ORDER BY 1"
#   schema  | tables
# ----------+--------
#  identity |      5
#  public   |      1
#
# Expect: exactly these two rows with these counts. The one public table is the
# migration tracking table, schema_migrations_identity.
```

**Check C — Vault is actually reachable.** Nothing so far has proved it, so prove it
now rather than discovering it when the first developer signs up:

```bash
VAULT_ADDR=https://vault.internal:8200 VAULT_TOKEN=<the service's token> \
  vault kv list ramp-agents/agents
# Expect: either a list of agent subdomains, or "No value found at
# ramp-agents/metadata/agents" on a fresh deployment. Both are success.
# "permission denied" means the token's policy is wrong —
# deploy/storage/vault/CONFIGURATION.md §3.
```

**Check D — it tells agent software where to sign in.**

```bash
curl -s https://id.example/.well-known/oauth-authorization-server
# Expect: JSON whose "issuer", "authorization_endpoint", "token_endpoint" and
# "registration_endpoint" all begin with your IDENTITY_AUTH_ISSUER, e.g.
# {"authorization_endpoint":"https://id.example/authorize",...,
#  "issuer":"https://id.example",...}
```

If those addresses show a different hostname, `IDENTITY_AUTH_ISSUER` is wrong and
sign-in will fail for everyone — it is published, not worked out from the request.

**Check E — the agent endpoint is protected.**

```bash
curl -s -i -X POST https://id.example/mcp \
  -H 'Content-Type: application/json' -d '{}' | head -4
# Expect:
# HTTP/1.1 401 Unauthorized
# Www-Authenticate: Bearer resource_metadata="https://id.example/.well-known/oauth-protected-resource"
#
# A 401 here is success: it is the endpoint telling agent software where to get a
# token. Anything other than 401 means the endpoint is unprotected — stop and
# investigate.
```

**Check F — the identity zone answers, and does not leak.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://nosuch.agents.example/.well-known/http-message-signatures-directory
# Expect: 404
```

A `404` for an agent that does not exist is correct. A `503` means Vault is
unreachable (Check C). A connection or certificate error means the wildcard DNS record
or the certificate does not cover the zone (§8).

Once a developer has signed up, the same address under **their** subdomain returns
their public key as a JSON key set, and that is what the Broker and the Exchange
fetch. The end-to-end sign-up walkthrough is in [`RUNBOOK.md`](RUNBOOK.md) §4.2.

---

## 11. Stopping and removing

```bash
docker compose stop identity      # pause; the database and Vault keep their contents
docker compose down               # remove containers; named volumes survive
```

Stopping the Identity Service takes the agent-facing path down: agents cannot make
new requests, no developer can sign up, and no licensed content is delivered —
content is fetched by this service on the agent's behalf, so that stops with it. It
does **not** affect visitors reading the publisher's site, and it does not
invalidate delivery links already issued — though a link bound to an agent's key is
only usable through this service, so it waits until the service is back.

**It also takes down every agent's published key**, because those documents are served
by this process. The Broker and the Exchange cache a fetched key directory for up to
an hour, so a short restart is invisible for agents they have seen recently — but an
agent they have not seen, or one presenting a newly rotated key, fails verification
immediately, and a long outage eventually makes agent requests fail verification
everywhere.

Removing the database or the Vault contents is a different matter — the keys in Vault
cannot be recovered, and every agent would have to be created again.

---

## 12. Where to go next

This document ends once the Identity Service is deployed and verified. Everything you
do to it afterwards lives in [`RUNBOOK.md`](RUNBOOK.md):

| Task | Where |
|---|---|
| Registering and activating an agent, end to end | `RUNBOOK.md` §4.2 |
| Rotating an agent's key | `RUNBOOK.md` §4.2 |
| Revoking a key immediately | `RUNBOOK.md` §4.2 |
| Removing an agent's access to the endpoint | `RUNBOOK.md` §4.2 |
| Upgrading and rolling back | `RUNBOOK.md` §4.3 |
| Why running more than one instance is not supported | `RUNBOOK.md` §4.1 |
| What to alert on, and what to ignore | `RUNBOOK.md` §2.3 |
| Something is broken and you need to know why | `RUNBOOK.md` §3 |
| Backing up the keys | [`deploy/storage/vault/RUNBOOK.md`](../../deploy/storage/vault/RUNBOOK.md) §5 |

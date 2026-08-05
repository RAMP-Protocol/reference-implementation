# RAMP Exchange — Deployment Instructions

This document tells you, the DevOps engineer, everything you need to deploy the
RAMP Exchange on your own infrastructure. You do not need to read the source
code. Follow the steps in order.

Every setting mentioned here is described in full in
[`CONFIGURATION.md`](CONFIGURATION.md). Once the Exchange is running, day-to-day
operation is in [`RUNBOOK.md`](RUNBOOK.md).

Words that may be new are explained the first time they appear.

---

## 1. What the Exchange is, and where it sits

The Exchange is the publisher's side of the system. It owns the catalog of
licensed content, prices access to it, signs the offers agents buy, and issues the
signed delivery URL the agent finally fetches. It is also **the only component
that charges money** — no other component moves money.

```
Agent ──► Broker ──► Exchange ──► (signed link) ──► CDN ──► Origin
```

**One dependency to know about before you start.** The Exchange treats the Broker
as the final word on which signing keys have been withdrawn. It reads a document
the Broker publishes, over public HTTPS, and it **refuses to start** without an
address for that document (`EXCHANGE_BROKER_WELLKNOWN_URL`). The boot never
waits on the document itself: with the address set, the Exchange starts even
while the Broker is still unreachable. Until DNS for the Broker resolves, its
certificate is issued and the Broker process answers, every **signed** request
is rejected and the log shows `exchange.httpsig.broker_wellknown_unavailable`
warnings (§8). **That state clears by itself** the moment the document becomes
reachable — no restart is needed.

**And one thing to prepare before you start.** The Exchange needs **two**
PostgreSQL databases, not one. The second holds the register of agent accounts.
Both must exist before the container starts — the Exchange creates tables but
never databases. A missing `EXCHANGE_SOR_DSN`, or a database it names that does
not exist, is a crash that does **not** fix itself (§4, §8).

---

## 2. What you need before you start

| What | Where it goes | How to check you have it |
|---|---|---|
| A PostgreSQL database and a user that owns it | `EXCHANGE_DSN` | `psql "$EXCHANGE_DSN" -c 'select 1'` |
| **A second PostgreSQL database**, same user, for the account registry | `EXCHANGE_SOR_DSN` | `psql "$EXCHANGE_SOR_DSN" -c 'select 1'` |
| A Redis instance | `REDIS_URL` | `redis-cli -u "$REDIS_URL" ping` → `PONG` |
| A public hostname for the Exchange, with TLS | `EXCHANGE_DOMAIN` | `curl -sI https://exchange.example.com` returns anything but a DNS error |
| The address of your Broker's published document | `EXCHANGE_BROKER_WELLKNOWN_URL` | `curl -s https://broker.example.com/.well-known/ramp.json` returns JSON |
| An internal network range for the admin port | `ADMIN_ALLOWED_CIDRS` | You can name the CIDR your operators connect from |
| A container runtime | — | `docker version` |
| OpenSSL (to generate keys in §5) | — | `openssl version` |

**Check your TLS arrangement now, before anything else.** Read
[`CONFIGURATION.md`](CONFIGURATION.md) §4. The Exchange cannot sit behind a proxy
that accepts HTTPS and forwards plain HTTP — every signed request would fail. If
that is your plan, sort it out before deploying.

---

## 3. Build or pull the image

The image is published to the GitHub Container Registry. Set the version once —
this is the only place this document names one, and every command below reuses
it:

```bash
VERSION=1.0.0-rc.2
docker pull ghcr.io/ramp-protocol/exchange:$VERSION
```

There is no `latest` tag, so the version is never optional. A bare
`docker pull ghcr.io/ramp-protocol/exchange` fails rather than fetching
something recent.

In production, deploy the digest rather than the tag. A tag is a pointer, and
whoever holds write access to the registry can move it; a digest names the
content itself and cannot be repointed. Read the digest, then deploy that:

```bash
docker buildx imagetools inspect ghcr.io/ramp-protocol/exchange:$VERSION
docker pull ghcr.io/ramp-protocol/exchange@sha256:<the digest that printed>
```

To build it yourself instead. The tag is `dev` on purpose: a local build is not
the published artifact, and giving it the release tag invites someone to push it.

```bash
# Run this from the REPOSITORY ROOT, not from src/exchange.
# The build needs the shared internal/ directory as well as src/exchange/.
docker build -f src/exchange/Dockerfile -t ghcr.io/ramp-protocol/exchange:dev .
```

Facts about the image:

- **The published image is amd64 only.** There is no ARM build and no
  multi-architecture image. The build links a native library for the TigerBeetle
  ledger client, which needs a C toolchain and cannot build for a different
  processor type, so build it on an amd64 machine if you build it yourself. On an
  Apple Silicon laptop the published image runs under emulation. That is fine for
  looking at it and wrong for measuring it.
- It is a *distroless* image (no shell, no package manager) and runs as an
  unprivileged user, **uid 65532**. Any key or configuration file you mount must
  be readable by that uid.
- It publishes **port 8081** only, matching the `EXCHANGE_ADDR` default. The
  admin listener's port is deliberately not published — see §7.
- The image declares no health check of its own, and there is no shell or
  `curl` inside it to write one with. The binary is its own probe instead:
  a container health check that runs `["CMD", "/exchange", "healthcheck"]`
  makes the binary call its own `/healthz` and exit 0 or 1. Or probe
  `/healthz` from outside.

---

## 4. Step 1 — prepare PostgreSQL

The Exchange needs **two databases** and a user that **owns** both. Create them
however you normally would; nothing else is required. In particular:

- **No PostgreSQL extensions are needed.**
- PostgreSQL 16 is the tested version.
- Both databases can live on the same PostgreSQL instance, and that instance can
  be shared with the Broker. The Exchange touches only what it creates.

| Database | Named by | The Exchange creates in it | Migration record |
|---|---|---|---|
| Catalog | `EXCHANGE_DSN` | Schema `ramp` — the catalog, the transaction log, the evidence store, the audit log, the tenants and the agents | `public.schema_migrations_ramp` |
| Account registry | `EXCHANGE_SOR_DSN` | Schema `sor` — one table, `sor.agent_accounts`, holding one row per registered agent | `public.schema_migrations_sor` |

**Two databases, not two schemas in one.** The Exchange opens a separate
connection for each and keeps a separate migration record in each. Point both
variables at one database and the two schemas would land side by side; that is
not the tested arrangement, so give the registry its own database.

Create both, connecting as a user allowed to create databases. `OWNER ramp` makes
the Exchange's own role the owner, which the next section requires:

```bash
ADMIN="postgres://postgres:PASSWORD@db.internal:5432/postgres"

psql "$ADMIN" -c 'CREATE DATABASE ramp OWNER ramp'
# Expect: CREATE DATABASE

psql "$ADMIN" -c 'CREATE DATABASE ramp_sor OWNER ramp'
# Expect: CREATE DATABASE
```

**The Exchange never creates a database.** It creates schemas and tables inside
databases you made first. If `EXCHANGE_SOR_DSN` names a database that does not
exist, the Exchange exits at boot with a message beginning `sor: setup database:`
and keeps exiting until you create it.

**You do not run migrations yourself.** The Exchange applies its own database
migrations automatically when it starts, before it begins listening — first in
the catalog database, then in the account registry. If either set fails, the
Exchange exits rather than serving traffic on a half-built schema.

Two consequences worth planning for:

1. **Start one instance first.** Every instance runs the migration step on start.
   They coordinate with a database lock so nothing corrupts, but the clean
   sequence is: start one, confirm it is healthy, then start the rest.
2. **A failed migration blocks every instance.** If a migration is interrupted
   halfway, PostgreSQL keeps a "dirty" marker and no instance will start until it
   is cleared. Escalate rather than editing the marker by hand.

Verify you can reach **both** databases as the owning user:

```bash
psql "$EXCHANGE_DSN" -c "select current_user, current_database()"
# Expect: one row naming your user and the catalog database

psql "$EXCHANGE_SOR_DSN" -c "select current_user, current_database()"
# Expect: one row naming the same user and the account-registry database
```

Neither the `ramp` schema nor the `sor` schema exists yet — both are created on
first start. Confirming that they were created correctly is Check E in §9.

### Using an existing PostgreSQL instance

`EXCHANGE_DSN` and `EXCHANGE_SOR_DSN` are ordinary PostgreSQL connection
strings, so they can point at an instance you already run rather than a new one
deployed alongside the Exchange. That is supported. The requirements are only
these, and they apply to both:

- A **dedicated database or a dedicated owning role.** The Exchange creates the
  `ramp` schema, its tables, two enum types and one trigger function inside
  whatever database `EXCHANGE_DSN` names, and the `sor` schema with its single
  table inside whatever database `EXCHANGE_SOR_DSN` names. Give each a database
  of its own if you can; if you must share, the role in the DSN has to be able
  to create a schema there.
- **The role owns what it creates.** Migrations run as the connecting role, and
  later migrations alter and drop what earlier ones made. A role with only
  `INSERT`/`SELECT` grants will fail on the first start.
- **`sslmode=require`** (or stricter) on any DSN that leaves the host.
- **Reachability from every Exchange instance**, with enough connections
  available for each — the Exchange holds a pool per process.

Nothing else is assumed: no specific PostgreSQL user name, no pre-created tables,
no extensions. Backup and tuning for the instance itself are in
[`deploy/storage/postgres/DEPLOYMENT.md`](../../deploy/storage/postgres/DEPLOYMENT.md).

---

## 5. Step 2 — generate the Exchange's keys

The Exchange uses **two separate keypairs**. They do different jobs and are not
interchangeable. The Ed25519 key is mandatory at boot; the RSA key is needed
only once a publisher uses AWS CloudFront — the callout below explains.

| Keypair | What it does | Set via |
|---|---|---|
| **Ed25519** | Signs every offer, and signs delivery URLs for publishers on the Ed25519 scheme. Its public half is published at `https://<your-exchange>/.well-known/http-message-signatures-directory`. | `RAMP_ED25519_PRIVATE_PEM_FILE` |
| **RSA** | Signs delivery URLs for publishers fronted by AWS CloudFront. | `RAMP_RSA_PRIVATE_PEM_FILE` |

```bash
openssl genpkey -algorithm ED25519 -out ed25519-private.pem
# Expect: no output, and a file whose first line is -----BEGIN PRIVATE KEY-----

openssl genrsa -out rsa-private.pem 2048
# Expect: a file whose first line is the same PKCS#8 "BEGIN PRIVATE KEY" header
#         (or the PKCS#1 "BEGIN RSA PRIVATE KEY" variant)
```

That `BEGIN PRIVATE KEY` header is the PKCS#8 form, which is the only Ed25519
format the Exchange accepts. The Broker's identity key is *not* in this format —
do not reuse a Broker key here, or a key generated here in the Broker.

> **The RSA key is only needed once a publisher uses CloudFront.** An
> all-Ed25519 deployment boots and runs without one — the Exchange notes the
> absence at start-up and refuses only the requests of a CloudFront-scheme
> publisher, telling you (in its log) what to set. Add the key the moment you
> onboard a CloudFront publisher. A key you do supply is checked at boot, so a
> corrupt one still stops the start. See
> [`CONFIGURATION.md`](CONFIGURATION.md) §2.2.

Store both in your secret manager, mount them into the container readable by uid
65532, and point the two `*_PEM_FILE` variables at them. If your secret store
injects values as environment variables rather than files, use
`RAMP_ED25519_PRIVATE_PEM` and `RAMP_RSA_PRIVATE_PEM` instead — the Exchange
accepts either and prefers the inline value.

> The keys in `deploy/` in this repository are **test files whose private keys are
> published here**. Generate your own; do not deploy the committed ones.

---

## 6. Step 3 — run it

Give the container the environment from [`CONFIGURATION.md`](CONFIGURATION.md) §6
and mount the key files. A minimal Docker Compose service:

```yaml
services:
  exchange:
    # A digest, not a tag — §3 explains why production pins the content itself.
    image: ghcr.io/ramp-protocol/exchange@sha256:<the digest from §3>
    restart: unless-stopped
    ports:
      - "8081:8081"                     # public listener only — see §7
    environment:
      EXCHANGE_DSN: "postgres://ramp:${DB_PASSWORD}@db.internal:5432/ramp?sslmode=require"
      # Second database, for the agent-account registry. Create it first (§4).
      EXCHANGE_SOR_DSN: "postgres://ramp:${DB_PASSWORD}@db.internal:5432/ramp_sor?sslmode=require"
      REDIS_URL: "rediss://:${REDIS_PASSWORD}@cache.internal:6379/0"
      EXCHANGE_DOMAIN: "exchange.example"
      EXCHANGE_PUBLIC_ORIGIN: "https://exchange.example"
      EXCHANGE_DEFAULT_TENANT: "www.publisher.example"
      EXCHANGE_BROKER_WELLKNOWN_URL: "https://broker.example/.well-known/ramp.json"
      EXCHANGE_REVOCATION_POLL_INTERVAL: "5m"
      RAMP_ED25519_PRIVATE_PEM_FILE: "/keys/ed25519-private.pem"
      RAMP_RSA_PRIVATE_PEM_FILE: "/keys/rsa-private.pem"
      ADMIN_ADDR: "127.0.0.1:8082"
      ADMIN_ALLOWED_CIDRS: "10.0.4.0/24"
      RAMP_BILLING_ADAPTER: "tigerbeetle"
      EXCHANGE_BILLING_LEDGER: "978"
      EXCHANGE_BILLING_TB_ADDRESS: "10.0.6.20:3000"
    volumes:
      - ./keys:/keys:ro                 # readable by uid 65532
```

Start it, then confirm it came up cleanly:

```bash
docker compose logs exchange | head -20
# Expect these lines, in this order:
#   {"level":"INFO","msg":"migrations applied","version":25,"dirty":false,"table":"schema_migrations_ramp"}
#   {"level":"INFO","msg":"ed25519 signing key loaded"}
#   {"level":"INFO","msg":"rsa signing key loaded"}
#   {"level":"INFO","msg":"billing adapter: tigerbeetle","ledger":978,"currency":"EUR", ...}
#   {"level":"INFO","msg":"migrations applied","version":1,"dirty":false,"table":"schema_migrations_sor"}
#   {"level":"INFO","msg":"sor adapter: postgres","cache_ttl":"30s"}
#   {"level":"INFO","msg":"exchange.httpsig.replay_store_ready","addr":"cache.internal:6379"}
#   {"level":"INFO","msg":"exchange.httpsig.wellknown_enabled","well_known_url":"https://broker...", ...}
#   {"level":"INFO","msg":"exchange listening","addr":":8081"}
#   {"level":"INFO","msg":"admin listening","addr":"127.0.0.1:8082"}
```

**`migrations applied` appears twice, and that is correct.** The first line
carries `"table":"schema_migrations_ramp"` and its `version` is the catalog
schema's. The second carries `"table":"schema_migrations_sor"` and its `version`
is the account registry's, which is much lower because that schema is newer. Read
the `table` field before comparing any version number.

One more line may appear, between `rsa signing key loaded` and
`billing adapter`, and it is a warning rather than an error:

```
{"level":"WARN","msg":"default tenant not found yet — Register will fail until it is seeded","default_tenant_domain":"www.publisher.example"}
```

That is expected on a first boot, before you have created any publisher. It is
**not** expected afterwards: while it appears, no agent can register and
therefore no agent can buy. Create the tenant (`RUNBOOK.md` §4.2) and restart.

Read the rest of the list as a checklist, because several of the lines are
absent rather than wrong when a setting is missing:

| Missing line | What it means |
|---|---|
| `exchange.httpsig.replay_store_ready` | `REDIS_URL` is unset — you will see `exchange.httpsig.replay_store_disabled` in its place. Replay protection is per-process, which is unsafe above one instance. |
| `billing adapter: …` | You are on the default `free` adapter: every charge is approved and nothing is recorded. |
| `sor adapter: postgres` and the `schema_migrations_sor` line | The account registry never came up, so the Exchange is not running at all — this pair is not optional. Look for an `exchange.exit` whose `err` begins `sor:`. |
| `admin listening` | The admin handler failed to build, almost always an unparseable `ADMIN_ALLOWED_CIDRS` — but that is fatal, so check for `exchange.exit` too. |

And two lines that appear only when something needs your attention:

| Extra line | What it means |
|---|---|
| `default tenant not found yet …` (WARN) | No tenant row matches `EXCHANGE_DEFAULT_TENANT` (or `EXCHANGE_DOMAIN`). Agent registration fails until you create it. Boot continues. |
| `could not verify default tenant at boot` (WARN) | The check itself failed — usually the catalog database was briefly unreachable. Boot continues; re-check after start-up. |

A missing connection string needs no line on that checklist: the Exchange
refuses to start without either one, and says so as it exits.

```
{"level":"ERROR","msg":"exchange.exit","err":"EXCHANGE_DSN is required"}
{"level":"ERROR","msg":"exchange.exit","err":"sor: EXCHANGE_SOR_DSN is required for RAMP_SOR_ADAPTER=postgres"}
```

---

## 7. Step 4 — bind the admin listener correctly

The Exchange runs a **second listener** on `ADMIN_ADDR` (default `:8082`) that
carries the operator's admin API: overriding a tenant's fee rate and its
reporting policy. It is never mounted on the public port.

There is no login on it. The only check is the IP allowlist in
`ADMIN_ALLOWED_CIDRS`, and it has one constraint you must design around:

> **The allowlist reads the connection's own source address and deliberately does
> not consult `X-Forwarded-For`. A proxy in front therefore makes the allowlist
> useless** — every request appears to come from the proxy, and the proxy's
> address is either on the list (so everything is allowed) or off it (so nothing
> is). See `docs/architecture/adr-022-admin-transport-plane.md` §8.

The three rules that follow from that:

1. **Bind the admin port directly to an internal interface** — for example
   `ADMIN_ADDR=127.0.0.1:8082` reached over an SSH tunnel, or a private subnet
   address. Do not front it with a load balancer, an ingress, or a reverse proxy.
2. **Set `ADMIN_ALLOWED_CIDRS` to your operator ranges.** Empty means deny
   everything, which is the safe default but also means the admin API is unusable
   until you set it. An unparseable entry stops the Exchange booting and names
   the offending token.
3. **Do not publish the admin port from the container** and keep it off the
   public ingress, out of any security group that the internet can reach.

The default `:8082` is worth a second look: it is the same port the Broker
publishes on. If you run both services on one host with host networking, change
one of them.

---

## 8. Step 5 — first-boot problems, and which ones clear by themselves

A correctly configured Exchange starts on the first attempt: the boot never
waits on reaching the Broker. Two failure shapes exist on day one, and they
look different in the logs. Tell them apart before touching anything.

**Shape 1 — the process is up, but signed requests are rejected.** The Broker's
document is fetched at runtime. On day one it stays unreachable
until all three of these are true: DNS for the Broker's hostname resolves, its
TLS certificate has been issued, and the Broker process is answering. Until
then the Exchange runs, its health checks pass, and every signed request is
refused — you will see WARN lines, not exits:

```bash
docker compose logs exchange | grep broker_wellknown_unavailable | tail -3
# Expect (transiently, on day one):
#   {"level":"WARN","msg":"exchange.httpsig.broker_wellknown_unavailable", ...}
```

This clears by itself the moment the document becomes reachable — no restart
is needed. If it persists after the Broker answers, confirm
`/.well-known/ramp.json` returns JSON from the Exchange's own network, and
that `EXCHANGE_BROKER_WELLKNOWN_URL` has no typo.

**Shape 2 — the process exits, restarts, and exits again.** A crash-loop is a
configuration fault, and it does **not** clear by itself. Read the `err` field
of the `exchange.exit` line and match it here:

| `err` begins with | Cause | Fix |
|---|---|---|
| `EXCHANGE_BROKER_WELLKNOWN_URL is required` | The variable is unset | Set it. The address is mandatory at boot, even though the document itself is only fetched at runtime. |
| `sor: EXCHANGE_SOR_DSN is required …` | The variable is unset | Set it. §2, §4. |
| `sor: setup database:` | The account-registry database does not exist, is unreachable, or the user cannot create a schema in it | Create the database and grant the user (§4). |
| `sor: unknown RAMP_SOR_ADAPTER` | A typo in `RAMP_SOR_ADAPTER` | Remove the variable — the default is correct. |
| `sor: invalid EXCHANGE_SOR_CACHE_TTL` | The value is not a duration | Use a form like `30s` or `1m`, or remove the variable. |

Every row in that table needs a change from you: the Exchange will restart
forever until you make it.

---

## 9. Step 6 — verify the deployment

Seven checks. Run them in order; each one builds on the last.

**Check A — the Exchange is alive.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example/healthz
# Expect: 200

curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example/readyz
# Expect: 200
```

`/healthz` checks **one** database connection: the catalog one. It stays green with
the ledger down, the cache down, the Broker down and the account registry down.

`/readyz` additionally checks the billing ledger, when one is configured. Point your
load balancer's **readiness** probe at `/readyz` and its **liveness** probe at
`/healthz` — reversing them makes a routine ledger restart restart the Exchange.
Neither covers the cache, the Broker or the account registry; see
[`RUNBOOK.md`](RUNBOOK.md) §2.1.

**Check B — it advertises itself correctly.**

```bash
curl -s https://exchange.example/.well-known/ramp.json
# Expect: JSON containing "role":"ROLE_EXCHANGE", your own "domain", and an
#         "endpoint" equal to your EXCHANGE_PUBLIC_ORIGIN
```

The `domain` here must be the exact string the Broker has registered for you and
the exact string publishers name in their own manifests. A mismatch is silent and
produces empty offer lists.

**Check C — the signature directory serves your Ed25519 key.**

```bash
curl -s https://exchange.example/.well-known/http-message-signatures-directory
# Expect: JSON with a "keys" array containing one Ed25519 key
#         ("kty":"OKP","crv":"Ed25519")
```

Restart the Exchange and run this again. **The key must be identical.** If it
changed, the deployment is not reading the key file you think it is.

**Check D — the admin listener answers from inside and refuses from outside.** Run
the same call twice, once from a host inside `ADMIN_ALLOWED_CIDRS` and once from
one outside it:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://10.0.4.11:8082/ramp.admin.v1.AdminService/SetTenantFeeRate \
  -H 'Content-Type: application/json' -d '{}'
# Expect: 400 from inside the allowlist (it reached the service; the empty body
#             failed validation)
#         403 from outside
```

A `403` from inside means your CIDR is wrong. A `400` from outside means the
listener is reachable from where it should not be — stop and fix §7.

**Check E — migrations applied in both databases.** Two databases, two records;
check both.

```bash
psql "$EXCHANGE_DSN" -c "SELECT version, dirty FROM public.schema_migrations_ramp"
#  version | dirty
# ---------+-------
#       25 | f
#
# Expect: the version matching the release you deployed, and dirty = f.

psql "$EXCHANGE_SOR_DSN" -c "SELECT version, dirty FROM public.schema_migrations_sor"
#  version | dirty
# ---------+-------
#        1 | f
#
# Expect: a much lower version than above — this schema is newer — and dirty = f.
```

**`dirty = t` means a migration was interrupted.** No instance will start until it
is resolved. Escalate — do not clear the flag by hand.

**Check F — the default tenant exists.** Without it every agent registration
fails, and an agent that cannot register cannot buy. The Exchange only warns
about this at boot, so check it explicitly:

```bash
psql "$EXCHANGE_DSN" -c \
  "SELECT tenant_id, domain FROM ramp.tenants WHERE domain = '$EXCHANGE_DEFAULT_TENANT'"
# Expect: exactly one row.
#         Zero rows means no agent can register — create the tenant
#         (RUNBOOK.md §4.2) and re-run this check.
```

If `EXCHANGE_DEFAULT_TENANT` is unset, substitute `EXCHANGE_DOMAIN` — that is the
value the Exchange falls back to.

**Check G — key discovery reaches the Broker.** There is no trusted-key file:
every verification key is fetched from the key owner's own published documents.
Confirm the Broker's directory (the revocation authority and the source of the
relay key) is reachable from the Exchange host:

```bash
curl -s "$EXCHANGE_BROKER_WELLKNOWN_URL" | python3 -c "import json,sys;json.load(sys.stdin);print('ok')"
# Expect: ok
```

While that document is unreachable the Exchange rejects signed requests
(fail closed) and logs `exchange.httpsig.broker_wellknown_unavailable`.

---

## 10. Stopping and removing

```bash
docker compose stop exchange     # pause; database, Redis and ledger keep contents
# Expect: "Container ... Stopped"

docker compose down              # remove containers; named volumes survive
# Expect: "Container ... Removed" and "Network ... Removed"
```

Stopping the Exchange stops all buying and selling: agents can no longer
discover offers or buy, and no new delivery URLs are issued. It does **not**
affect visitors reading the publisher's site, and **delivery URLs already issued
keep working** until they expire — the CDN verifies them without asking the
Exchange.

The Broker keeps running and will simply return no offers for your content.

---

## 11. Where to go next

This document ends once the Exchange is deployed and verified. Everything you do
to it afterwards lives in [`RUNBOOK.md`](RUNBOOK.md):

| Task | Where |
|---|---|
| Onboarding a publisher end to end | `RUNBOOK.md` §4.2 |
| Getting an agent registered so it can buy | `RUNBOOK.md` §4.2 |
| Loading and refreshing the catalog | `RUNBOOK.md` §4.2 |
| Rotating the tenant signing key | `RUNBOOK.md` §4.2 |
| Changing a fee rate or reporting policy at runtime | `RUNBOOK.md` §4.2 |
| Upgrading and rolling back | `RUNBOOK.md` §4.3 |
| Running more than one instance | `RUNBOOK.md` §4.1 |
| Reading tenant configuration | `RUNBOOK.md` §4.1 |
| What to alert on, and what to ignore | `RUNBOOK.md` §2.3 |
| Something is broken and you need to know why | `RUNBOOK.md` §3 |

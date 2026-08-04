# RAMP Broker — Deployment Instructions

This document tells you, the DevOps engineer, everything you need to deploy the
RAMP Broker on your own infrastructure. You do not need to read the source code.
Follow the steps in order.

Every setting mentioned here is described in full in
[`CONFIGURATION.md`](CONFIGURATION.md). Once the Broker is running, day-to-day
operation is in [`RUNBOOK.md`](RUNBOOK.md).

Words that may be new are explained the first time they appear.

---

## 1. What the Broker is, and where it sits

The Broker is the front door for AI agents. An agent asks the Broker "what would it
cost to use these URLs?"; the Broker asks the relevant Exchange, ranks the answers
and hands them back. When the agent decides to buy, it sends that purchase to the
Broker, which forwards it to the Exchange. The Exchange returns a signed download
link.

```
Agent ──► Broker ──► Exchange ──► (signed link) ──► CDN ──► Origin
```

The Broker is **not** on the download path. It never holds an agent's private key,
never creates a download link, and never sees the content.

**One dependency to know about before you start.** The Exchange refuses to start
until it can read a document published by the Broker (it treats the Broker as the
final word on which keys have been withdrawn). So on a first deployment the
Exchange will start, fail and restart over and over — a *crash-loop* — for a few
minutes, until DNS resolves, certificates are issued and the Broker is answering.
**This is expected and fixes itself** — deploy both with a restart policy such as
`restart: unless-stopped` and let them keep retrying. Do not treat the early
Exchange restarts as a fault.

---

## 2. What you need before you start

| What | Where it goes | How to check you have it |
|---|---|---|
| A PostgreSQL database and a user that owns it | `BROKER_DSN` | `psql "$BROKER_DSN" -c 'select 1'` |
| A Redis instance | `REDIS_URL` | `redis-cli -u "$REDIS_URL" ping` → `PONG` |
| A public hostname for the Broker, with TLS | `BROKER_DOMAIN` | `curl -sI https://broker.example.com` returns anything but a DNS error |
| The address of the Exchange you route to | `BROKER_REGISTRY_FILE` (§7) | `curl -s https://exchange.example.com/.well-known/ramp.json` returns JSON |
| A container runtime | — | `docker version` |
| Python 3 (to generate keys in §5) | — | `python3 --version` |

**Check your TLS arrangement now, before anything else.** Read
[`CONFIGURATION.md`](CONFIGURATION.md) §4. The Broker cannot sit behind a proxy that
accepts HTTPS and forwards plain HTTP — every signed request would fail. If that is
your plan, sort it out before deploying.

---

## 3. Build or pull the image

The image is published to the GitHub Container Registry. Set the version once —
this is the only place this document names one, and every command below reuses
it:

```bash
VERSION=1.0.0-rc.1
docker pull ghcr.io/ramp-protocol/broker:$VERSION
```

There is no `latest` tag, so the version is never optional. A bare
`docker pull ghcr.io/ramp-protocol/broker` fails rather than fetching something
recent.

In production, deploy the digest rather than the tag. A tag is a pointer, and
whoever holds write access to the registry can move it; a digest names the
content itself and cannot be repointed. Read the digest, then deploy that:

```bash
docker buildx imagetools inspect ghcr.io/ramp-protocol/broker:$VERSION
docker pull ghcr.io/ramp-protocol/broker@sha256:<the digest that printed>
```

To build it yourself instead. The tag is `dev` on purpose: a local build is not
the published artifact, and giving it the release tag invites someone to push it.

```bash
# Run this from the REPOSITORY ROOT, not from src/broker.
# The build needs the shared internal/ directory as well as src/broker/.
docker build -f src/broker/Dockerfile -t ghcr.io/ramp-protocol/broker:dev .
```

Facts about the image:

- **The published image is amd64 only.** No ARM variant is published and there
  is no multi-architecture image. That is a publishing decision, not a limit of
  the code: the Broker is pure Go and cross-compiles, so you can build an ARM
  image yourself if you need one. On an Apple Silicon laptop the published image
  runs under emulation, which is fine for looking at it and wrong for measuring
  it.
- It is a *distroless* image (no shell, no package manager) and runs as an
  unprivileged user, **uid 65532**. Any key or configuration file you mount must be
  readable by that uid, and the directory holding the withdrawn-keys file must be
  writable by it if you intend to update that file in place.
- It publishes **port 8082**, matching the `BROKER_ADDR` default. If you change
  `BROKER_ADDR`, change the published port to match.

---

## 4. Step 1 — prepare PostgreSQL

The Broker needs a database and a user that **owns** it. Create them however you
normally would; nothing else is required. In particular:

- **No PostgreSQL extensions are needed.**
- PostgreSQL 16 is the tested version.
- The Broker creates and uses its own schema called `broker`. It does not touch
  anything else in the database, so it can share an instance with the Exchange.

**You do not run migrations yourself.** The Broker applies its own database
migrations automatically when it starts, before it begins listening. If a migration
fails, the Broker exits rather than serving traffic on a half-built schema.

Two consequences worth planning for:

1. **Start one instance first.** Every instance runs the migration step on start.
   They coordinate with a database lock so nothing corrupts, but the clean sequence
   is: start one, confirm it is healthy, then start the rest.
2. **A failed migration blocks every instance.** If a migration is interrupted
   halfway, PostgreSQL keeps a "dirty" marker and no instance will start until it is
   cleared. Escalate rather than editing the marker by hand.

Verify you can reach the database as the owning user:

```bash
psql "$BROKER_DSN" -c "select current_user, current_database()"
# Expect: one row naming your user and database
```

The `broker` schema does not exist yet — it is created on first start. Confirming
that it was created correctly is Check A in §8.

---

## 5. Step 2 — generate the Broker's keys

The Broker uses **two separate keypairs**. They do different jobs and are not
interchangeable.

| Keypair | What it does | Set via |
|---|---|---|
| **Identity key** | The Broker's public identity. Its public half is published at `https://<your-broker>/.well-known/http-message-signatures-directory` and cached by other parties for up to 90 days. | `BROKER_ED25519_SEED` |
| **Relay key** | Signs the Broker's outbound calls to the Exchange, so the Exchange knows the request really came from your Broker. | `BROKER_RELAY_KEY_FILE` |

### Generate the identity key

```bash
python3 -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())"
# Expect: a 43-character string, for example
# 3Qk1v8sJ0Xa2pR7mZbN4cT6hLwYuE9gD1fK5jHnOqSs
```

Store that string in your secret manager and supply it as `BROKER_ED25519_SEED`.

> **This is not optional.** The Broker refuses to start without an identity key, so
> that it never publishes one which disappears on the next restart. See
> [`CONFIGURATION.md`](CONFIGURATION.md) §2.

### Generate the relay key

```bash
BROKER_RELAY_KID=broker.example.v1 scripts/gen-broker-relay-key.sh
# Expect: "wrote deploy/broker/keys.json and deploy/broker/broker-key.json
#          (kid=broker.example.v1)"
```

This writes two files:

- `deploy/broker/broker-key.json` — the **private** key. Mount it into the Broker
  container and point `BROKER_RELAY_KEY_FILE` at it. Treat it as a secret.
- `deploy/broker/keys.json` — the **public** key, added to the shared list of keys
  the Exchange trusts. The Exchange operator must load this same file, otherwise it
  will reject your Broker's calls with `401`.

> The copies of these files already in the repository are **test fixtures with
> published private keys**. Generate your own; do not deploy the committed ones.

---

## 6. Step 3 — run it

Give the container the environment from [`CONFIGURATION.md`](CONFIGURATION.md) §6
and mount the key files. A minimal Docker Compose service:

```yaml
services:
  broker:
    # A digest, not a tag — §3 explains why production pins the content itself.
    image: ghcr.io/ramp-protocol/broker@sha256:<the digest from §3>
    restart: unless-stopped
    ports:
      - "8082:8082"
    environment:
      BROKER_DSN: "postgres://ramp:${DB_PASSWORD}@db.internal:5432/ramp?sslmode=require"
      REDIS_URL: "rediss://:${REDIS_PASSWORD}@cache.internal:6379/0"
      BROKER_ID: "broker-01"
      BROKER_DOMAIN: "broker.example"
      BROKER_ED25519_SEED: "${BROKER_ED25519_SEED}"
      BROKER_KEYS_FILE: "/keys/keys.json"
      BROKER_RELAY_KEY_FILE: "/keys/broker-key.json"
      BROKER_REGISTRY_FILE: "/config/exchanges.yaml"
      BROKER_REVOCATION_URL: "https://broker.example/.well-known/ramp-key-revocations.json"
      BROKER_REVOCATION_FILE: "/revocations/revocations.json"
    volumes:
      - ./keys:/keys:ro                  # readable by uid 65532
      - ./config:/config:ro
      - ./revocations:/revocations       # writable by uid 65532
```

Start it, then confirm it came up cleanly:

```bash
docker compose logs broker | head -20
# Expect these lines, in some order:
#   {"level":"INFO","msg":"migrations applied","version":3,"dirty":false, ...}
#   {"level":"INFO","msg":"broker.redis.ready","addr":"..."}
#   {"level":"INFO","msg":"broker.relay.signing","keyid":"0yN6xRMmYrgA78Ue3aR4..."}
#   {"level":"INFO","msg":"broker.registry.loaded","path":"/keys/keys.json","count":N}
#   {"level":"INFO","msg":"broker listening","addr":":8082"}
#
# The "keyid" is not the name you chose in BROKER_RELAY_KID — it is the key's
# fingerprint (an RFC 7638 thumbprint). That fingerprint is how every other
# party refers to the key, so keep it: you need it to withdraw the key
# (RUNBOOK.md §4.2).
```

If you see `broker.redis.disabled`, `broker.relay.key_absent` or
`broker.registry.absent` instead, a setting is missing — see
[`CONFIGURATION.md`](CONFIGURATION.md) §3 for what each one costs.

---

## 7. Step 4 — register your Exchange, and remove the demo entries

The Broker only routes to Exchanges on its list. The list lives in the YAML file you
pointed `BROKER_REGISTRY_FILE` at, and is loaded into the database at every start.

Create `/config/exchanges.yaml`:

```yaml
exchanges:
  - id: exchange-01
    domain: exchange.example
    endpoint: https://exchange.example
    trust_level: VERIFIED
    priority: 100
    supported_profiles:
      - ramp-news-v1
```

`trust_level` is one of `DISCOVERED`, `VERIFIED`, `PREFERRED`, `BLOCKED`. The
Broker considers **any** listed Exchange that is healthy and not `BLOCKED`. When
more than one has an offer, they are ranked by `trust_level` first (`PREFERRED`,
then `VERIFIED`, then `DISCOVERED`), then by the lower price, and `priority` only
breaks a remaining tie. Use `BLOCKED` to take an Exchange out of service without
deleting it.

Nothing else fills this list. With `BROKER_REGISTRY_FILE` unset the Broker starts
with no Exchanges at all — it logs `broker.registry.no_bootstrap` once and every
discovery then returns nothing.

Start-up only *adds and updates* rows, so removing an entry from the file later does
not remove the row. Deleting one for real is in [`RUNBOOK.md`](RUNBOOK.md) §4.1.

### Create the withdrawn-keys file

`BROKER_REVOCATION_FILE` points at a file the Broker publishes so the Exchange
knows which keys have been withdrawn. Create it now, empty, so it is in place from
day one:

Copy the example that ships with the repository and set `as_of` to the current UTC
time:

```bash
cp deploy/broker/revocations.example.json /revocations/revocations.json
cat /revocations/revocations.json
# Expect: {"as_of": "2026-01-01T00:00:00Z", "revoked": []}
```

Copy it — do not mount the repository file read-only. The Broker re-reads this file
whenever it changes, so it has to live on storage you can write to, readable (and
writable, if you update it in place) by uid 65532.

Adding keys to it is §9.

---

## 8. Step 5 — verify the deployment

Five checks. Run them in order; each one builds on the last.

**Check A — the Broker is alive.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://broker.example/healthz
# Expect: 200
```

Note this checks the database connection **only**. It stays green with Redis down —
see [`RUNBOOK.md`](RUNBOOK.md) §3.

**Check B — it advertises itself correctly.**

```bash
curl -s https://broker.example/.well-known/ramp.json | head -20
# Expect: JSON containing "role": "ROLE_BROKER" and your own domain
```

**Check C — it publishes a stable identity.**

```bash
curl -s https://broker.example/.well-known/http-message-signatures-directory
# Expect: JSON with a "keys" array, and a "revocation_url" field pointing at
#         your BROKER_REVOCATION_URL
```

Restart the Broker and run this again. **The keys must be identical.** If they
changed, the Broker is running with the ephemeral (throwaway) key setting turned on
([`CONFIGURATION.md`](CONFIGURATION.md) §2) and must be given a real seed instead.

**Check D — the withdrawn-keys channel is live.**

```bash
curl -s https://broker.example/.well-known/ramp-key-revocations.json
# Expect: JSON with an "as_of" timestamp close to now.
# If as_of is "1970-01-01T00:00:00Z", BROKER_REVOCATION_FILE is unset or the file
# is missing — the Exchange will believe no key has ever been withdrawn.
```

**Check E — the Exchange list contains exactly what you expect.**

```bash
psql "$BROKER_DSN" -c \
  "SELECT exchange_id, domain, trust_level, healthy FROM broker.exchanges"
#  exchange_id     |         domain         | trust_level | healthy
# -----------------+------------------------+-------------+---------
#  exchange-01 | exchange.example | VERIFIED  | t
#
# Expect: only your own Exchange rows, with healthy = t. Any mp.*.example row
# means §7 was not completed.
```

**If `healthy` is `f`, stop and fix it now.** A new row starts healthy; it flips to
`f` only after a failed health probe, which means the Broker could not reach that
Exchange's `/healthz` at the moment it checked. That is a genuine misconfiguration —
a wrong `endpoint`, DNS not resolving yet, or the Exchange not up.

It matters more than it looks: **once an Exchange is marked unhealthy the Broker
stops probing it altogether**, so it will not recover when the Exchange comes back,
and it will not recover when you restart the Broker. Fix the cause, then clear the
flag by hand — the procedure is in [`RUNBOOK.md`](RUNBOOK.md) §4.1.

---

## 9. Stopping and removing

```bash
docker compose stop broker      # pause; database and Redis keep their contents
docker compose down             # remove containers; named volumes survive
```

Stopping the Broker stops agents using the platform: they can no longer discover
offers or make purchases. It does **not** affect visitors reading the publisher's
site, and it does not invalidate download links already issued.

Note that a stopped Broker will also prevent the **Exchange** from starting, because
the Exchange requires the Broker's published documents at boot (§1). Bring the
Broker back before restarting the Exchange.

---

## 10. Where to go next

This document ends once the Broker is deployed and verified. Everything you do to it
afterwards lives in [`RUNBOOK.md`](RUNBOOK.md):

| Task | Where |
|---|---|
| Rotating the identity or relay key | `RUNBOOK.md` §4.2 |
| Withdrawing a compromised key immediately | `RUNBOOK.md` §4.2 |
| Upgrading and rolling back | `RUNBOOK.md` §4.3 |
| Adding, removing or quarantining an Exchange | `RUNBOOK.md` §4.1 |
| Bringing an Exchange back after it was marked unhealthy | `RUNBOOK.md` §4.1 |
| Running more than one instance | `RUNBOOK.md` §4.1 |
| What to alert on, and what to ignore | `RUNBOOK.md` §2.3 |
| Something is broken and you need to know why | `RUNBOOK.md` §3 |

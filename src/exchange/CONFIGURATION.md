# RAMP Exchange — Configuration Reference

This document lists every setting the Exchange understands, what each one does,
and what happens if you leave it out. It is a reference, not a procedure — for
the step-by-step install see [`DEPLOYMENT.md`](DEPLOYMENT.md), and for day-to-day
operation see [`RUNBOOK.md`](RUNBOOK.md).

Audience: the DevOps engineer deploying the Exchange. You do not need to read the
source code. Words that may be new are explained the first time they appear.

---

## 1. What the Exchange needs to run

The Exchange is a single Go binary in a container. It needs:

| Dependency | Required? | Why |
|---|---|---|
| PostgreSQL — **two separate databases** | **Yes** | The first holds the catalog, the transaction log, the evidence store and the audit log (`EXCHANGE_DSN`). The second holds the account registry (`EXCHANGE_SOR_DSN`). The binary exits if either connection string is unset. Both must exist before the Exchange starts — see §2.1. |
| An Ed25519 private key | **Yes** | Signs offers and signed delivery URLs. The binary exits without one. |
| An RSA private key | Only for AWS CloudFront publishers | Signs AWS CloudFront delivery URLs. An all-Ed25519 deployment boots and runs without one; a CloudFront publisher's requests are refused until it is added — see §2.2. |
| The Broker's address | **Yes** | The Broker publishes the list of withdrawn keys. The Exchange refuses to start without an address for it (`EXCHANGE_BROKER_WELLKNOWN_URL`). The boot never waits on reaching the Broker: while the Broker cannot be fetched, the Exchange runs but rejects signed requests — see §2.3. |
| Redis | Strongly recommended | Stops the same signed request being replayed. Without it the Exchange still runs, but the protection is per-process (see §2.1). |
| TigerBeetle | Only for `tigerbeetle` billing | The money ledger. Not needed for the default `free` adapter. |

It listens on **two ports**: the public Exchange listener (`EXCHANGE_ADDR`,
default `:8081`) and a separate internal admin listener (`ADMIN_ADDR`, default
`:8082`). The container image publishes 8081 only.

Three things are worth knowing up front because operators often look for them and
they do not exist:

- **There are no command-line flags.** Configuration is 100% environment
  variables, and there is no configuration file. The binary does accept one
  subcommand: `exchange healthcheck` probes its own `/healthz` and exits,
  so a container health check can run the service binary itself.
- **There is no `LOG_LEVEL`.** The Exchange always writes structured JSON logs at
  `INFO` level to standard output. ("Structured" means each log line is
  machine-readable data, not free text.) `DEBUG` lines are never emitted.
- **There is no `/metrics` endpoint** and no Prometheus support. Alerting is done
  on log events — see [`RUNBOOK.md`](RUNBOOK.md) §2.2.

### How values are read

Two parsing rules apply throughout and are worth stating once:

- **An empty string counts as unset.** `EXCHANGE_DOMAIN=""` gives you the default
  `exchange.ramp.local`, not an empty domain. There is no way to set a setting to
  the empty string on purpose.
- **The on/off settings are strict.** A switch is on only for exactly `true`
  (any case) or `1`; **any other value means off**. So a typo like
  `RAMP_TRUST_PROXY_HEADERS=flase` silently means *off* — after setting a
  switch, confirm the behaviour changed rather than assuming. This one rule
  covers every on/off setting the Exchange reads, `SKIP_SSRF` and
  `ALLOW_INSECURE` included — see §2.4.

---

## 2. Environment variables

"Required" means the Exchange will not start without it. Two connection strings
carry that mark: `EXCHANGE_DSN` and `EXCHANGE_SOR_DSN`. Everything else has a
default, but several of the defaults are **not** safe for production — those are
called out in §3 and §5.

### 2.1 Core and listeners

| Name | Required? | What it is | Example |
|---|---|---|---|
| `EXCHANGE_DSN` | **Required** | The PostgreSQL connection string for the catalog database. The Exchange exits immediately if this is unset. | `postgres://ramp:PASSWORD@db.internal:5432/ramp?sslmode=require` |
| `EXCHANGE_SOR_DSN` | **Required** | The PostgreSQL connection string for the **account registry**, a **second, separate database**. Not a second schema in the catalog database — a different database. The Exchange exits immediately if this is unset. See §2.6. | `postgres://ramp:PASSWORD@db.internal:5432/ramp_sor?sslmode=require` |
| `RAMP_SOR_ADAPTER` | Optional | Which account registry to use. Only `postgres` exists, and it is the default. **Any other value stops the boot** — see §2.6. | *(leave unset)* |
| `EXCHANGE_SOR_CACHE_TTL` | Optional | How long the Exchange reuses an account's on/off status before re-reading it. Default `30s`. A value it cannot parse stops the boot. | `30s` |
| `EXCHANGE_DEFAULT_TENANT` | Optional, **set it** | The publisher whose "activate new agents automatically" policy applies when an agent registers. Falls back to `EXCHANGE_DOMAIN` when unset. **If no tenant row matches this name, every agent registration fails** — the Exchange warns about it at boot (§2.6). | `www.publisher.example` |
| `EXCHANGE_DEFAULT_AGENT_CREDIT` | Optional | One-time credit granted to each newly registered agent, in **whole units** of the deployment ledger currency — `100` on an EUR ledger grants €100.00 per agent, not 100 cents. This variable is the **sole owner** of the default tenant's `default_agent_credit` column: every boot replaces the stored value with it, and unset (or `0`) disables the grant on the next restart — there is no admin RPC, and a value edited into the database by hand does not survive a restart. A plain decimal only — digits with an optional fraction, at most 8 decimal places. **Anything else stops the boot.** | `100` |
| `EXCHANGE_ADDR` | Optional | Address the public listener binds to. Default `:8081`. The image publishes 8081, so change the published port too if you change this. | `:8081` |
| `ADMIN_ADDR` | Optional | Address the internal admin listener binds to. Default `:8082`. Bind it to an internal interface — see [`DEPLOYMENT.md`](DEPLOYMENT.md) §7. | `127.0.0.1:8082` |
| `ADMIN_ALLOWED_CIDRS` | Optional, **set it** | Comma-separated IPs and CIDR ranges permitted to call the admin listener. **Empty means deny everything.** An unparseable entry stops the Exchange booting, naming the token. | `10.0.4.0/24,10.0.5.17` |
| `RAMP_TRUST_PROXY_HEADERS` | **Required** behind a TLS-terminating proxy, forbidden otherwise | Makes signature verification use the scheme from `X-Forwarded-Proto`, so requests signed for `https` verify behind a proxy that forwards plain `http`. Only the exact values `true` or `1` enable it — anything else keeps it off. **Never set it on a directly-exposed Exchange** — see §4. | `true` |
| `EXCHANGE_DOMAIN` | Optional, **set it** | The public hostname of this Exchange. Written into the documents it publishes and into every offer it signs, and it is the key a publisher's own manifest is matched against, so it must be the name callers actually use. Default `exchange.ramp.local`. | `exchange.example` |
| `EXCHANGE_PUBLIC_ORIGIN` | Optional | The origin (scheme + host) advertised as this Exchange's RPC endpoint. Default `https://<EXCHANGE_DOMAIN>`. It must match the endpoint the Broker has registered for you. | `https://exchange.example` |
| `REDIS_URL` | Optional, **set it** | Redis connection string, used to remember which signed requests have already been seen. Username, password and TLS all travel inside the URL; there is no separate variable for them. Leave it unset and each process remembers on its own — see the warning below. | `rediss://:PASSWORD@cache.internal:6379/0` |
| `EXCHANGE_MAX_INTERMEDIARY_HOPS` | Optional | How many relay hops a signed request may carry. Default `4`. A non-numeric or out-of-range value silently falls back to `4` (§3). | `4` |
| `EXCHANGE_CATALOG_URI_SCHEME` | Optional | Overrides the scheme written into stored catalog URLs. Default `https`. Leave unset in production. | *(leave unset)* |

#### `REDIS_URL` — what "unset" actually costs

With `REDIS_URL` unset the Exchange keeps a private, in-process record of which
signed requests it has already seen, and says so at boot:

```
{"level":"INFO","msg":"exchange.httpsig.replay_store_disabled"}
```

With it set you get `exchange.httpsig.replay_store_ready` instead, carrying the
address. Exactly one of the two appears on every boot, so `replay_store` is the
single string to grep for the answer.

- With **one** Exchange instance, this works.
- With **two or more**, it does not: a request already used against instance A is
  still unknown to instance B, so it can be replayed there. **Nothing but that
  one log line tells you** — the requests themselves succeed either way.

If you run more than one instance, `REDIS_URL` is mandatory, and every instance
must point at **the same** Redis. Do not give each instance its own. Redis's own
settings are in [`deploy/storage/redis/CONFIGURATION.md`](../../deploy/storage/redis/CONFIGURATION.md).

### 2.2 Signing keys

The Exchange never generates a signing key for itself: a key that changed on
every restart would invalidate every URL and offer signed before it. So a key
that is needed and missing stops the boot rather than being invented.

The **Ed25519 key is always needed** — every publisher's offers are signed with
it — so it is mandatory at boot. The **RSA key is needed only by publishers on
the AWS CloudFront scheme**, and is optional for a deployment that has none. See
below.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `RAMP_ED25519_PRIVATE_PEM` | **Required** (or the file below) | The Ed25519 private key used to sign offers and Ed25519 delivery URLs, supplied inline as PEM text. **PKCS#8 only** — the `-----BEGIN PRIVATE KEY-----` form `openssl genpkey` writes. | that header, then the base64 body |
| `RAMP_ED25519_PRIVATE_PEM_FILE` | Alternative to the above | Path to the same key as a file. Read only when the inline variable is empty. A path that is set but unreadable is a boot failure. | `/keys/ed25519-private.pem` |
| `RAMP_RSA_PRIVATE_PEM` | Required **only** for AWS CloudFront publishers (or the file below) | The RSA private key used to sign AWS CloudFront delivery URLs, supplied inline as PEM text. Accepts both the PKCS#1 `BEGIN RSA PRIVATE KEY` header and the PKCS#8 `BEGIN PRIVATE KEY` one. | either header, then the base64 body |
| `RAMP_RSA_PRIVATE_PEM_FILE` | Alternative to the above | Path to the same key as a file. | `/keys/rsa-private.pem` |
| `RAMP_DEMO_ED25519_KEY_REF` | Optional | Internal name the Ed25519 key is filed under. Default `exchange-primary`. Changing it has no external effect. | *(leave at default)* |
| `RAMP_DEMO_RSA_KEY_REF` | Optional | Internal name the RSA key is filed under. Default `cf-rsa-primary`. | *(leave at default)* |

#### When the RSA key is needed, and what happens when it is missing

Each publisher chooses one of two ways its delivery URLs are signed: **Ed25519**
(verified by the Cloudflare or Fastly worker) or **AWS CloudFront RSA** (verified
natively by CloudFront). A deployment where every publisher is on Ed25519 never
uses an RSA key for anything, and does not need one.

Leaving it out is safe rather than silent. At start-up the Exchange notes that it
has no RSA key and carries on:

```
{"level":"INFO","msg":"no RSA signing key configured; AWS_CLOUDFRONT_RSA tenants will be refused","rsa_key_ref":"cf-rsa-primary"}
```

If a CloudFront publisher is then configured, the request that would need the key
is refused with the `failed_precondition` code. The calling agent sees only a
short message ("delivery URL signing is not provisioned for this publisher") —
which variables supply the key is operator knowledge, so the full refusal lands
in the Exchange's own log, where you will read it:

```
no RSA signing key: this tenant signs delivery URLs with the AWS_CLOUDFRONT_RSA
scheme, which needs one — set RAMP_RSA_PRIVATE_PEM or RAMP_RSA_PRIVATE_PEM_FILE
```

Two consequences worth knowing:

- A key you **do** supply is read at start-up, so one that is corrupt or in the
  wrong format stops the boot immediately instead of failing on the first
  CloudFront delivery. Supplying a key means it gets checked.
- Nothing else changes for Ed25519 publishers. Add the RSA key the moment you
  onboard a CloudFront publisher; the generation command is in
  [`DEPLOYMENT.md`](DEPLOYMENT.md) §5. Treat it as a real secret.

The Ed25519 key, being needed by every publisher, does stop the boot when it is
missing:

```
{"level":"ERROR","msg":"exchange.exit","err":"no Ed25519 signing key: set RAMP_ED25519_PRIVATE_PEM or RAMP_ED25519_PRIVATE_PEM_FILE"}
```

### 2.3 HTTP-signature verification and key resolution

Callers sign their requests using a scheme called HTTP Message Signatures
(RFC 9421). These settings control which keys the Exchange will accept.

There is no key file. The Exchange learns every verification key over the
network, from the key owner's own published documents:

1. **The Broker's directory first** (`EXCHANGE_BROKER_WELLKNOWN_URL`). It
   carries the Broker's relay key and the withdrawn-key list, and its verdict
   on a withdrawn or expired key is final.
2. **The signer's own directory second.** For any other key, the Exchange
   fetches the directory named by the request's signed `Signature-Agent`
   header and looks the key up there. A signer that does not publish its key
   gets `401`.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `EXCHANGE_BROKER_WELLKNOWN_URL` | **Required** | The address of the Broker's published document. The Exchange consults the Broker's withdrawn-key list *first* on every verification, and resolves the Broker's own relay key from the same document. Boot fails without it — see below. | `https://broker.example/.well-known/ramp.json` |
| `EXCHANGE_REVOCATION_POLL_INTERVAL` | Optional | How often to re-read the Broker's withdrawn-key list. Unset leaves the built-in interval in place. A malformed value silently falls back (§3). | `5m` |
| `EXCHANGE_DIRECTORY_TTL` | Optional | How long a fetched key directory is cached. Unset leaves the built-in TTL in place. A malformed value silently falls back (§3). | `10m` |

#### `EXCHANGE_BROKER_WELLKNOWN_URL` is mandatory, by design

Without an address for the Broker, the Exchange has nothing to check the
withdrawn-key list against: a key that had been withdrawn would keep working for
as long as the signer's own directory still published it. Rather than warn and
boot anyway, the Exchange refuses to start:

```
EXCHANGE_BROKER_WELLKNOWN_URL is required: refusing to boot without a revocation
authority ahead of the per-agent well-known path (a revoked key would otherwise
keep verifying)
```

The same principle applies at runtime: if the Broker's document cannot be
fetched, signed requests are **rejected**, not let through. The Exchange logs
`exchange.httpsig.broker_wellknown_unavailable` and refuses the request rather
than risk accepting a withdrawn key. See [`RUNBOOK.md`](RUNBOOK.md) §2.3.

### 2.4 Public documents and outbound fetches

| Name | Required? | What it is | Example |
|---|---|---|---|
| `RAMP_WELLKNOWN_SCHEME` | Optional | Which protocol the Exchange uses when fetching other parties' public documents. Default `https`. **Must stay `https` in production.** | `https` |
| `RAMP_WELLKNOWN_PORT` | Optional | Appends a port when fetching those documents. Only needed inside a local test network. Leave unset. | *(leave unset)* |
| `SKIP_SSRF` | Optional — **leave unset** | Setting this removes the guard that stops the Exchange being tricked into calling internal addresses. Development only. | *(leave unset)* |
| `ALLOW_INSECURE` | Optional — **leave unset** | Setting this allows plain unencrypted `http` for those same calls. Development only. | *(leave unset)* |
| `EXCHANGE_REGISTRATION_SCHEMA` | Optional | A JSON Schema describing the registration details this Exchange expects. Published in its `/.well-known/ramp.json`. A schema the Exchange cannot use stops the boot. See below. | *(leave unset)* |
| `EXCHANGE_TERMS_URI` | Optional | The address of your terms of service document. Published in the same place. See below. | *(leave unset)* |
| `EXCHANGE_TERMS_DIGEST` | Optional | The digest pinning which revision of that document. Requires `EXCHANGE_TERMS_URI`. See below. | *(leave unset)* |

`SKIP_SSRF` and `ALLOW_INSECURE` follow the same strict rule as every other
on/off setting (§1): they are on only for exactly `true` (any case) or `1`.
Every other value — including `yes`, `on`, and a typo like `ture` — leaves the
guard in place. For these two switches the rule matters most: each one removes
a protection, so a typo must leave the protection on.

#### What agents must send to open an account, and which terms they accept

Three optional settings are published in the Exchange's own
`/.well-known/ramp.json`. All three are unset by default, and unset means the
Exchange behaves exactly as it does without them: it accepts whatever
registration details an agent sends, and it names no terms document.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `EXCHANGE_REGISTRATION_SCHEMA` | Optional | A JSON Schema describing the registration details this Exchange expects, written inline. Published as `account_registration.data_schema`. Agents read it and check their details against it before they send, so setting it is how you tell them what you need. Unset means no schema is published and agents send whatever they hold. A schema the Exchange cannot use **stops the boot** — see below. | `{"type":"object","required":["company_name"],"properties":{"company_name":{"type":"string","minLength":1}}}` |
| `EXCHANGE_TERMS_URI` | Optional | The address of your terms of service document. Published as `terms_uri`. | `https://exchange.example/terms/2026-04` |
| `EXCHANGE_TERMS_DIGEST` | Optional | The digest of the document served at `EXCHANGE_TERMS_URI`, written as the method, a colon, then lowercase hex: `sha256:` and 64 characters, `sha384:` and 96, or `sha512:` and 128. Published as `terms_digest`. Use SHA-256 unless you have a reason not to. Setting it **without** `EXCHANGE_TERMS_URI` stops the boot, and so does a value in any other shape. | `sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` |

Produce the digest from the file you actually serve:

```
printf 'sha256:%s\n' "$(sha256sum terms-2026-04.html | cut -d' ' -f1)"
```

**Why the digest and not just the URL.** A URL says where your terms are, not
which version an operator agreed to. Its content changes, so after your first
revision every earlier registration points at a document that no longer says
what was agreed. The digest names one exact revision. A registering agent reads
it from your manifest and echoes it back in its request, where the agent's own
signature covers it — so the request states which document its operator
accepted. That only holds while the document is still retrievable, so **keep
every terms revision you have published online**; a digest of a deleted
document identifies nothing.

**Publishing the digest turns the check on.** A registration must then name this
exact digest. One that names a different digest is refused, and so is one that
names none at all — the caller would be claiming acceptance of terms it never
identified. Both refusals carry the same reason, `TERMS_DIGEST_STALE`, because
both have the same remedy: fetch the terms document this Exchange publishes, hash
it, and register again. The accepted digest is then stored with the account, so
you can answer later which revision an account agreed to.

The check runs on FIRST registration only. An account that already exists gets
its stored `billing_ref` back unchanged, and nothing is accepted a second time —
publishing a new terms revision does not break the replay that repeat Register
calls rely on.

**Leave `EXCHANGE_TERMS_DIGEST` unset and none of that happens.** No digest is
published, so a value an agent sends is ignored and none is recorded.

**Plan on changing the digest being coordinated rather than free.** Agents echo
the value they last read from your manifest, so every agent holding the old value
is refused until it re-reads your manifest. Publish the new terms document first
and change the variable second, so the value you advertise always names a
document that is actually being served.

**Publishing the schema is what turns enforcement on.** A payload that does not
match it is refused, and the refusal names every member that failed and why, so
an agent can fix them all in one go rather than one per round trip. Leave the
variable unset and a payload reaches the system of record uninspected, exactly as
before the field existed.

The bounds on registration data apply either way, and they come from the protocol
rather than from this Exchange: at most 64 top-level members, at most 32 levels of
nesting, and at most 16 KB once the payload is written in its canonical (RFC 8785)
form. A payload over a bound is refused as a malformed request, which is a
different answer from "does not match your schema" — an agent that reads the
distinction knows whether to shrink the payload or to correct it.

**A schema the Exchange cannot use stops the boot**, naming what is wrong. It
is not dropped with a warning: an Exchange that silently published nothing
would leave every agent unable to learn what you require while you believed the
requirement was published, and the first evidence would be a registration
arriving without the details you asked for. The rules a published schema must
satisfy come from the protocol, because the agent checking its details against
your schema applies exactly the same ones:

- **JSON Schema draft 2020-12 only.** A `$schema` naming any other draft is refused.
- **Self-contained.** Every `$ref` must point inside the same document, and must
  start with `#`. A reference to another host is refused: an Exchange's manifest
  is read by strangers, and a reference that leaves the document turns every
  reader into a fetcher aimed at an address the schema's author chose.
- **Bounded.** At most 16 KB, at most 32 levels of nesting, and a limit on how
  much work checking one registration against it may cost. A reference chain
  may not loop back on itself. The 16 KB is measured on the schema as it is
  published, not as you wrote it, so indentation and line breaks in the value
  you set do not count against it.
- **Portable patterns.** A `pattern` may only use the regular-expression
  features all three protocol SDKs express identically, so your schema means the
  same thing to every agent that reads it.

A schema describing a business — a company name, a billing email, a tax id —
sits far inside all of these.

**A value that is only whitespace counts as unset.** All three settings are read
with surrounding whitespace removed, so a template that rendered to a blank line
leaves the setting unconfigured rather than publishing the blank. The boot log
line `registration settings resolved` reports what each one resolved to, which
is where to look when a value you set does not appear in the served document.

**`{}` is a published schema, not an absent one.** An empty JSON object is a
valid schema that accepts every payload, so setting the variable to `{}` — or
to a template that rendered empty — publishes the block and tells agents this
Exchange has requirements, while requiring nothing. To publish no schema, leave
the variable unset or empty.

### 2.5 Billing

`RAMP_BILLING_ADAPTER` chooses the money backend. The chosen backend's own
settings all live under the `EXCHANGE_BILLING_` prefix.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `RAMP_BILLING_ADAPTER` | Optional | One of `free`, `inmemory`, `tigerbeetle`. Default `free` — every charge is approved and nothing is recorded. An **unrecognised value logs a warning and falls back to `free`**, so a typo here means you are not billing at all. | `tigerbeetle` |
| `EXCHANGE_BILLING_SEED` | `inmemory` only | JSON object of starting balances, `{"agent-id": {"value": "100.00", "currency": "USD"}}`. **`USD` is the only accepted currency** — the `inmemory` tier denominates every balance in it, and a balance in another currency can neither receive the Register welcome credit nor be spent safely. Entries that are malformed, or in any other currency, are logged and skipped; that agent simply starts with no balance. | *(leave unset)* |
| `EXCHANGE_BILLING_LEDGER` | **Required** for `tigerbeetle` | The ISO 4217 **numeric** currency code, which is also the ledger id. Only `978` (EUR) and `840` (USD) are supported; anything else is a boot failure. | `978` |
| `EXCHANGE_BILLING_TB_ADDRESS` | **Required** for `tigerbeetle` | TigerBeetle address as `IP:port`. **Hostnames are rejected** — supply an IP. | `10.0.6.20:3000` |
| `EXCHANGE_BILLING_TB_CLUSTER_ID` | Optional | TigerBeetle cluster id. Default `0`. A non-numeric value is a boot failure. | `0` |
| `EXCHANGE_BILLING_HOLD_GRACE` | Optional | How long a reservation outlives the delivery URL. Default `1m`, giving a 6-minute hold against the 5-minute URL. A malformed value is a boot failure. | `1m` |
| `EXCHANGE_BILLING_TB_OP_TIMEOUT` | Optional | Deadline for a single ledger call. Unset leaves the built-in 5s. A malformed value is a boot failure. | `5s` |

**A selected TigerBeetle that cannot be reached fails the boot.** It never
quietly falls back to `free`. The Exchange constructs the client, runs a health
check, and exits on failure with `billing: TigerBeetle health check: …`. That is
the intended behaviour: a billing service that quietly stops charging is worse
than one that will not start.

The ledger's own configuration — cluster sizing, data file, replicas — is in
[`deploy/storage/tigerbeetle/CONFIGURATION.md`](../../deploy/storage/tigerbeetle/CONFIGURATION.md)
rather than repeated here.

### 2.6 The account system of record

The **system of record**, or **SoR**, is the Exchange's register of agent
accounts. An agent that wants to buy paid content calls the `Register` RPC once.
The Exchange writes a row here, gives the agent a `billing_ref` — the identifier
its money is keyed on — and stores that same `billing_ref` on the agent's row in
the catalog database. An agent with no `billing_ref` cannot buy anything.

`RAMP_SOR_ADAPTER` chooses the backend, exactly as `RAMP_BILLING_ADAPTER` does
for money. The chosen backend's own settings all live under the
`EXCHANGE_SOR_` prefix. Both are listed in §2.1; the three points below are what
make this section worth reading.

**The SoR needs its own database, and you must create it yourself.** The
Exchange opens a *second* connection to `EXCHANGE_SOR_DSN` and applies its own
migrations there at boot, creating the schema `sor` and the table
`sor.agent_accounts`. It never issues `CREATE DATABASE`, so the database has to
exist before the container starts. Pointing `EXCHANGE_SOR_DSN` at the same
database as `EXCHANGE_DSN` is not the intended arrangement — keep them separate.

**A typo in `RAMP_SOR_ADAPTER` stops the boot; a typo in `RAMP_BILLING_ADAPTER`
does not.** This is deliberate and it is the one contrast to remember:

| Selector | Unrecognised value | Consequence |
|---|---|---|
| `RAMP_BILLING_ADAPTER` | Warns, falls back to `free` | The service runs and approves every charge. Survivable, but you are not billing. |
| `RAMP_SOR_ADAPTER` | **Exits** with `sor: unknown RAMP_SOR_ADAPTER "…"` | The service does not start. Not survivable — and that is the point: there is no safe empty account register to fall back to. |

**A missing default tenant is warned about, not fatal.** At boot the Exchange
looks for the tenant named by `EXCHANGE_DEFAULT_TENANT` (or `EXCHANGE_DOMAIN` if
that is unset). If there is no such row it logs a warning and carries on, because
you may create tenants after the process starts:

```
{"level":"WARN","msg":"default tenant not found yet — Register will fail until it is seeded","default_tenant_domain":"www.publisher.example"}
```

Take the warning seriously. Until that tenant row exists, **every** agent
registration is refused, so no agent can buy anything.

---

### 2.7 Request-size limits (fixed, not configurable)

Two limits are compiled in rather than read from the environment, so there is
nothing to set — but they decide what a caller may send, and a refusal that
names neither is hard to place. Both are **1 MiB**, one number applied to both
quantities on the two mounts an agent or a publisher reaches: the
ExchangeService RPCs and the catalog push.

The admin listener is not one of them and carries neither bound. Its protection
is reachability — a separate port, bound to an internal interface, behind an
IP allowlist that denies by default — and an operator who can reach it can
already call every setter. Closing that gap is tracked separately; it is
recorded here rather than left for a reader to infer from a table that does not
mention the mount.

| Bounded quantity | Refusal a caller sees | Why it is bounded |
|---|---|---|
| The raw HTTP body, buffered before the caller is known | HTTP 413 with a `resource_exhausted` Connect body, logged as `outcome=body_too_large` | An RFC 9421 signature is checked over the exact bytes, so the body must be read before it can be verified. Without the bound an unauthenticated caller could spend the Exchange's memory. |
| The decompressed Connect message the handler decodes | `resource_exhausted` | A compressed request inflates at a ratio the caller picks, and the protocol's own list bounds do not limit the work of checking one. |

Consequences worth knowing. A catalog push carries at most 256 entries by
protocol rule, and this size limit applies on top of that — a feed of unusually
large entries can produce a submission that satisfies the count bound and
crosses this one, which the ingest RUNBOOK's §3.1 covers. The `Register` RPC
adds a tighter, semantic bound on `registration_data` itself; this is the outer
wall, that is the inner one.

---

## 3. Settings that take a default silently when malformed

Most bad values stop the boot and name themselves. Three do not — they fall back
to a default with **no log line**, so the Exchange runs with settings you did not
choose and nothing tells you.

| Setting | On a malformed value | Why it matters |
|---|---|---|
| `EXCHANGE_MAX_INTERMEDIARY_HOPS` | Falls back to `4`. Non-numeric, negative, or above 1048576 all qualify. | The value is published to Brokers as the number of relay hops you accept. |
| `EXCHANGE_REVOCATION_POLL_INTERVAL` | Falls back to the built-in interval. A negative duration also qualifies. | You may believe you are polling the withdrawn-key list every minute when you are not. |
| `EXCHANGE_DIRECTORY_TTL` | Falls back to the built-in TTL. | A rotated key may be picked up later than you planned. |

After changing any of these, confirm the value took effect rather than assuming:
the poll interval is echoed in the `exchange.httpsig.wellknown_enabled` boot line,
and the hop count appears in the published `/.well-known/ramp.json`.

---

## 4. If you terminate TLS in front of the Exchange — read this

**Behind a proxy that terminates HTTPS, you must set
`RAMP_TRUST_PROXY_HEADERS=true` — and set it ONLY there.**

Agents and Brokers sign their requests using HTTP Message Signatures (RFC 9421).
Part of what gets signed is the full request URL — *including whether it was
`http` or `https`*. The Exchange reconstructs that URL from the connection it
actually received.

So if a reverse proxy (Caddy, nginx, an AWS load balancer) accepts `https://` from
the caller and forwards plain `http://` to the Exchange without this flag, the
caller signed one URL and the Exchange checks a different one. **Every signed
request fails verification**, and the logs show a stream of
`exchange.httpsig.reject` with `outcome=signature`. The service looks healthy;
nothing works.

With `RAMP_TRUST_PROXY_HEADERS=true`, the Exchange reads the scheme from the
`X-Forwarded-Proto` header the proxy sets, so verification runs against the
`https` URL the caller actually signed. The staging compose stack (Caddy in
front) deploys exactly this shape.

Rules for using it safely:

- **Set it only behind a proxy you control.** On a directly-exposed Exchange
  the header comes from the caller, and honoring it lets the caller pick the
  scheme its signature is verified against. That is why the flag is off unless
  the value is exactly `true` or `1` — any other value (including a typo) keeps
  it off.
- **The proxy must replace, not append to, any incoming `X-Forwarded-Proto`.**
  Caddy and AWS ALB do this by default. A proxy that appends would leave the
  first (caller-supplied) value in charge.
- Only the scheme is trusted. `X-Forwarded-Host` is deliberately ignored: the
  proxy preserves the `Host` header, and honoring a forwarded host would let a
  request signed for one endpoint verify at another.

Without the flag, the older options still work: terminate TLS in pass-through
mode, or put no TLS-terminating proxy in front. The admin listener has a
separate, unrelated limit — see [`DEPLOYMENT.md`](DEPLOYMENT.md) §7.

---

## 5. Development defaults you must not copy

The compose files in this repository exist to run automated tests on a private
network. Several of their settings are deliberately unsafe and must never be
carried into production:

| Setting | Why it is there | Why it must not ship |
|---|---|---|
| `RAMP_WELLKNOWN_SCHEME: "http"` | The test network has no certificates. | Public documents would be fetched unencrypted and could be tampered with in transit. |
| `SKIP_SSRF: "true"` | Test services live on private addresses the guard blocks. | Removes the protection against the Exchange being steered into your internal network. |
| `ALLOW_INSECURE: "true"` | Same reason. | Same consequence. |
| `EXCHANGE_CATALOG_URI_SCHEME: "http"` | Compose traffic is http-only. | Every catalog URL would be stored as plaintext `http`. |
| `sslmode=disable` in the DSN | The database is on the same private bridge. | Correct only while the connection stays on one host. On a network you do not control exclusively TLS is required: without it every row travels in the clear, and what the login exposes depends on the cluster's authentication method ([`deploy/storage/postgres/CONFIGURATION.md`](../../deploy/storage/postgres/CONFIGURATION.md) §2.3). |
| `RAMP_BILLING_ADAPTER: "inmemory"` | The test suite needs a deny path without a real ledger. | Balances live in process memory and vanish on restart. Nothing is ever settled. |

---

## 6. Worked example

Values marked *fill in* are specific to your environment.

```
EXCHANGE_DSN=postgres://ramp:<password>@<db-host>:5432/ramp?sslmode=require
EXCHANGE_SOR_DSN=postgres://ramp:<password>@<db-host>:5432/ramp_sor?sslmode=require
EXCHANGE_ADDR=:8081
ADMIN_ADDR=127.0.0.1:8082
ADMIN_ALLOWED_CIDRS=10.0.4.0/24
EXCHANGE_DOMAIN=exchange.example
EXCHANGE_PUBLIC_ORIGIN=https://exchange.example
EXCHANGE_DEFAULT_TENANT=www.publisher.example
REDIS_URL=rediss://:<password>@<redis-host>:6379/0
RAMP_ED25519_PRIVATE_PEM_FILE=/keys/ed25519-private.pem
RAMP_RSA_PRIVATE_PEM_FILE=/keys/rsa-private.pem
EXCHANGE_BROKER_WELLKNOWN_URL=https://broker.example/.well-known/ramp.json
EXCHANGE_REVOCATION_POLL_INTERVAL=5m
RAMP_BILLING_ADAPTER=tigerbeetle
EXCHANGE_BILLING_LEDGER=978
EXCHANGE_BILLING_TB_ADDRESS=<tigerbeetle-ip>:3000
```

Everything not listed is left at its default. In particular `SKIP_SSRF`,
`ALLOW_INSECURE`, `RAMP_WELLKNOWN_PORT` and `EXCHANGE_CATALOG_URI_SCHEME` stay
unset, `RAMP_WELLKNOWN_SCHEME` stays at its `https` default, and
`RAMP_SOR_ADAPTER` stays at its `postgres` default.

Note the **two** databases: `ramp` and `ramp_sor`. Both must already exist —
[`DEPLOYMENT.md`](DEPLOYMENT.md) §4 creates them.

The secret values above (`EXCHANGE_DSN`, `EXCHANGE_SOR_DSN`, `REDIS_URL`, and the
two signing keys) are read as plain environment variables. The Exchange does not
know or care where they came from, so the secret store and the tooling that
supplies them are your choice — the only requirement is that they are present in
the environment when the process starts.

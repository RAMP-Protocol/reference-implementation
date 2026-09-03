# RAMP Broker — Configuration Reference

This document lists every setting the Broker understands, what each one does, and
what happens if you leave it out. It is a reference, not a procedure — for the
step-by-step install see [`DEPLOYMENT.md`](DEPLOYMENT.md), and for day-to-day
operation see [`RUNBOOK.md`](RUNBOOK.md).

Audience: the DevOps engineer deploying the Broker. You do not need to read the
source code. Words that may be new are explained the first time they appear.

---

## 1. What the Broker needs to run

The Broker is a single Go binary in a container. It needs:

| Dependency | Required? | Why |
|---|---|---|
| PostgreSQL | **Yes** | Holds the list of Exchanges the Broker routes to, plus an audit log. The binary exits if it cannot reach it. |
| Redis | Strongly recommended | Stops the same signed request being replayed. Without it the Broker still runs, but the protection is per-process (see §2). |
| A reachable Exchange | Yes, at runtime | The Broker reads each Exchange's public `/.well-known/ramp.json` to find its address. |

It listens on **one port, `:8082`**. There is no admin port and no second listener.

Three things are worth knowing up front because operators often look for them and
they do not exist:

- **There are no command-line flags.** Configuration is 100% environment variables.
- **There is no `LOG_LEVEL`.** The Broker always writes structured JSON logs at
  `INFO` level to standard output. ("Structured" means each log line is
  machine-readable data, not free text.)
- **There is no `/metrics` endpoint** and no Prometheus support. Alerting is done
  on log events — see [`RUNBOOK.md`](RUNBOOK.md) §2.2.

---

## 2. Environment variables

"Required" means the Broker will not start without it. Everything else has a
default, but several of the defaults are **not** safe for production — those are
called out in §3 and §5.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `BROKER_DSN` | **Required** | The PostgreSQL connection string. The Broker exits immediately if this is unset. | `postgres://ramp:PASSWORD@db.internal:5432/ramp?sslmode=require` |
| `BROKER_ADDR` | Optional | The address the Broker listens on. Default `:8082`. The container image publishes port 8082, so if you change this you must change the published port too. | `:8082` |
| `RAMP_TRUST_PROXY_HEADERS` | **Required** behind a TLS-terminating proxy, forbidden otherwise | Makes signature verification use the scheme from `X-Forwarded-Proto`, so requests signed for `https` verify behind a proxy that forwards plain `http`. Only the exact values `true` or `1` enable it — anything else keeps it off. **Never set it on a directly-exposed Broker** — see §4. | `true` |
| `REDIS_URL` | Optional, **set it** | Redis connection string, used to remember which signed requests have already been seen. Leave it unset and each process remembers on its own — see the warning below. Username, password and TLS all travel inside the URL; there is no separate variable for them. | `rediss://:PASSWORD@cache.internal:6379/0` |
| `BROKER_ID` | Optional | A short name for this Broker, used in the documents it publishes. Default `broker-local`. | `broker-01` |
| `BROKER_DOMAIN` | Optional | The public hostname of this Broker. It is written into the documents the Broker publishes and into the signatures it makes, so it must match the name callers actually use. Default `broker.local`. | `broker.example` |
| `BROKER_RELAY_KEY_FILE` | Optional, **set it** | Path to the **private** key the Broker signs its outbound calls to the Exchange with. Default `deploy/broker/broker-key.json`. Without it those calls go out unsigned and the Exchange answers `401`. | `/relay/broker-key.json` |
| `BROKER_ED25519_SEED` | **Required** (or the file below) | The Broker's own signing key, as 32 raw bytes in base64url. This is the identity the Broker publishes to the world. The Broker will not start without it — see below. | `<43-character base64url string>` |
| `BROKER_ED25519_KEY_FILE` | Alternative to the seed | The same key supplied as a PEM file. Only read when `BROKER_ED25519_SEED` is empty. Note the format problem in §3. | `/keys/cosign.pem` |
| `BROKER_REVOCATION_URL` | Optional, **set it** | The public web address where the Broker publishes its list of withdrawn keys. The Exchange polls this. If unset, the Broker does not advertise it and the Exchange has nothing to poll. | `https://broker.example/.well-known/ramp-key-revocations.json` |
| `BROKER_REVOCATION_FILE` | Optional | Path to the file whose contents are served at the address above. If unset or missing, the Broker serves an empty "nothing has ever been withdrawn" answer, dated 1 January 1970, forever. The file is re-read when it changes — no restart needed. | `/revocations/revocations.json` |
| `BROKER_REGISTRY_FILE` | Optional, **set it** | Path to a YAML file listing the Exchanges this Broker routes to. Nothing else fills that list, so with this unset the Broker starts with no Exchanges and every discovery returns nothing. | `/config/exchanges.yaml` |
| `EXA_API_KEY` | Optional | The key for the EXA search service. It is used only for requests that carry a free-text query and no URLs: EXA turns the query into candidate publisher domains. With it unset, every such request fails at once with `no domains for query`. Requests that name a URL directly never use it. Even with a key, the free-text path returns no offers yet — see [`RUNBOOK.md`](RUNBOOK.md) §6. | *(unset unless you serve free-text queries)* |
| `RAMP_WELLKNOWN_SCHEME` | Optional | Which protocol the Broker uses when fetching other parties' public documents. Default `https`. **Must stay `https` in production.** | `https` |
| `RAMP_WELLKNOWN_PORT` | Optional | Appends a port when fetching those documents. Only needed inside a local test network. Leave unset. | *(leave unset)* |
| `SKIP_SSRF` | Optional — **leave unset** | Setting this to `true` removes the guard that stops the Broker being tricked into calling internal addresses. Development only. | *(leave unset)* |
| `ALLOW_INSECURE` | Optional — **leave unset** | Setting this to `true` allows plain unencrypted `http` for those same calls. Development only. | *(leave unset)* |
| `BROKER_ALLOW_EPHEMERAL_KEY` | Optional — **leave unset** | Setting this to `true` lets the Broker start without an identity key, creating an ephemeral (throwaway) one that changes on every restart. Development only. | *(leave unset)* |

### `REDIS_URL` — what "unset" actually costs

With `REDIS_URL` unset the Broker still starts, logs one `INFO` line
(`broker.redis.disabled`) and carries on. Each process then keeps its own private
record of which signed requests it has already seen.

- With **one** Broker instance, this works.
- With **two or more**, it does not: a request already used against instance A is
  still unknown to instance B, so it can be replayed there. Nothing warns you.

If you run more than one Broker instance, `REDIS_URL` is mandatory, and every
instance must point at **the same** Redis. Do not give each instance its own.

### The identity key is mandatory

The Broker publishes its own public key in a directory that other parties fetch and
cache. Each published key carries a 90-day validity window, and consumers such as
the Exchange re-fetch the directory on their own schedule — once an hour by
default. A key that changed on every restart would leave everybody
holding one that no longer verifies — so the Broker **refuses to start** when neither
`BROKER_ED25519_SEED` nor `BROKER_ED25519_KEY_FILE` is set, rather than creating one
for you:

```
{"level":"ERROR","msg":"broker.exit","err":"signer setup: no Broker identity key: ..."}
```

There is one way out, and it is for development and CI only: setting
`BROKER_ALLOW_EPHEMERAL_KEY` to `true` or `1` restores the throwaway-key behaviour.
It is parsed strictly — any other value, including a typo like `flase`, leaves the
requirement in place. **Never set it in production**; see §5.

---

## 3. The file settings, and what happens when one is missing

Four settings point at files. Two of them fail quietly, which makes them the
most common source of "it deployed fine but nothing works".

There is no key file for verification: the Broker learns an agent's public key
by fetching the directory named by the request's signed `Signature-Agent`
header. An agent that does not publish its key gets `401`.

| Setting | If the file is missing | If the file is present but broken |
|---|---|---|
| `BROKER_RELAY_KEY_FILE` | Warning `broker.relay.key_absent`, Broker starts, **outbound calls to the Exchange are unsigned** and get `401`. | The Broker **refuses to start**. |
| `BROKER_ED25519_KEY_FILE` | The Broker **refuses to start** unless `BROKER_ED25519_SEED` is set instead (see §2). | The Broker **refuses to start**. |
| `BROKER_REGISTRY_FILE` | The Broker **refuses to start** — the open error appears in `broker.exit`. The quiet case is leaving the variable **unset**: then no Exchange is registered, every discovery returns nothing, and the only signal is one `broker.registry.no_bootstrap` warning at start-up. | The Broker **refuses to start**. |
| `BROKER_REVOCATION_FILE` | Serves an empty list dated `1970-01-01T00:00:00Z` forever — the Exchange concludes no key has ever been withdrawn. | Returns HTTP `500` on that one route; the rest of the Broker keeps working. The log line `broker.revocation.unavailable` carries the validation error. |

The withdrawn-keys file is the one file you edit while the Broker is running — it is
re-read whenever it changes, no restart needed. A ready-to-copy starting file ships as
`deploy/broker/revocations.example.json`; the format and the procedure for adding a key
are in [`RUNBOOK.md`](RUNBOOK.md) §4.2.

### The Exchange list only ever grows

Start-up *adds and updates* rows from `BROKER_REGISTRY_FILE`; it never deletes.
Removing an entry from the file therefore leaves the row in place, and removing an
Exchange for real takes one SQL statement — see [`RUNBOOK.md`](RUNBOOK.md) §4.1.

### The Ed25519 PEM format problem

If you supply the Broker's key via `BROKER_ED25519_KEY_FILE`, note that the
obvious command produces the wrong format:

```bash
openssl genpkey -algorithm ED25519 -out cosign.pem   # DOES NOT WORK
```

OpenSSL writes a 48-byte PKCS#8 wrapper; the Broker expects the 64-byte raw key
(seed followed by public key) as the PEM block's payload and rejects anything
else. Do not write this file by hand. The staging deploy delivers the key this
way on purpose — a root-owned key file, never an env value inside the
world-readable compose file — and its generator,
`deploy/terraform/scripts/gen-staging-keys.sh`, writes
`broker-identity-key.pem` in exactly the shape the loader wants. Outside that
deploy path, `BROKER_ED25519_SEED` remains the simpler choice with no format
to get wrong. The generation command is in [`DEPLOYMENT.md`](DEPLOYMENT.md) §5.

One more detail: the generator labels the block `ED25519 PRIVATE KEY`, and the
staging Terraform checks for that label before deploying — but the Broker's own
loader checks only the payload length, not the label. A file that passes the
Broker can still be refused by Terraform's stricter plan-time check.

---

## 4. If you terminate TLS in front of the Broker — read this

**Behind a proxy that terminates HTTPS, you must set
`RAMP_TRUST_PROXY_HEADERS=true` — and set it ONLY there.**

Agents sign their requests using a scheme called HTTP Message Signatures
(RFC 9421). Part of what gets signed is the full request URL — *including whether
it was `http` or `https`*. The Broker reconstructs that URL from the connection it
actually received.

So if a reverse proxy (Caddy, nginx, an AWS load balancer) accepts `https://` from
the agent and forwards plain `http://` to the Broker without this flag, the agent
signed one URL and the Broker checks a different one. **Every signed request fails
verification**, and the logs show a stream of `broker.httpsig.reject` with
`outcome=signature`. The service looks healthy; nothing works.

With `RAMP_TRUST_PROXY_HEADERS=true`, the Broker reads the scheme from the
`X-Forwarded-Proto` header the proxy sets, so verification runs against the
`https` URL the agent actually signed. The staging compose stack (Caddy in
front) deploys exactly this shape.

Rules for using it safely:

- **Set it only behind a proxy you control.** On a directly-exposed Broker the
  header comes from the caller, and honoring it lets the caller pick the scheme
  its signature is verified against. That is why the flag is off unless the
  value is exactly `true` or `1` — any other value (including a typo) keeps it
  off.
- **The proxy must replace, not append to, any incoming `X-Forwarded-Proto`.**
  Caddy and AWS ALB do this by default. A proxy that appends would leave the
  first (caller-supplied) value in charge.
- Only the scheme is trusted. `X-Forwarded-Host` is deliberately ignored: the
  proxy preserves the `Host` header, and honoring a forwarded host would let a
  request signed for one endpoint verify at another.

Without the flag, the older options still work: terminate TLS in pass-through
mode, or put no TLS-terminating proxy in front.

---

## 5. Development defaults you must not copy

The compose files in this repository exist to run automated tests on a private
network. Several of their settings are deliberately unsafe and must never be
carried into production:

| Setting | Why it is there | Why it must not ship |
|---|---|---|
| `RAMP_WELLKNOWN_SCHEME: "http"` | The test network has no certificates. | Public documents would be fetched unencrypted and could be tampered with in transit. |
| `SKIP_SSRF: "true"` | Test services live on private addresses the guard blocks. | Removes the protection against the Broker being steered into your internal network. |
| `ALLOW_INSECURE: "true"` | Same reason. | Same consequence. |
| `sslmode=disable` in the DSN | The database is on the same private bridge. | Correct only while the connection stays on one host. On a network you do not control exclusively TLS is required: without it every row travels in the clear, and what the login exposes depends on the cluster's authentication method ([`deploy/storage/postgres/CONFIGURATION.md`](../../deploy/storage/postgres/CONFIGURATION.md) §2.3). |
| `BROKER_ALLOW_EPHEMERAL_KEY: "true"` | Tests are torn down between runs, so nothing caches the Broker's identity. | Every restart changes the identity the Broker publishes, and everyone who cached it is left holding a key that no longer verifies. |

---

## 6. Worked example

Values marked *fill in* are specific to your environment.

```
BROKER_DSN=postgres://ramp:<password>@<db-host>:5432/ramp?sslmode=require
BROKER_ADDR=:8082
REDIS_URL=rediss://:<password>@<redis-host>:6379/0
BROKER_ID=broker-01
BROKER_DOMAIN=broker.example
BROKER_RELAY_KEY_FILE=/keys/broker-key.json
BROKER_ED25519_SEED=<fill in — see DEPLOYMENT.md §5>
BROKER_REGISTRY_FILE=/config/exchanges.yaml
BROKER_REVOCATION_URL=https://broker.example/.well-known/ramp-key-revocations.json
BROKER_REVOCATION_FILE=/revocations/revocations.json
```

Everything not listed is left at its default. In particular `EXA_API_KEY`,
`SKIP_SSRF`, `ALLOW_INSECURE` and `RAMP_WELLKNOWN_PORT` stay unset, and
`RAMP_WELLKNOWN_SCHEME` stays at its `https` default.

The secret values above (`BROKER_DSN`, `REDIS_URL`, `BROKER_ED25519_SEED`) are read
as plain environment variables. The Broker does not know or care where they came
from, so the secret store and the tooling that supplies them are your choice — the
only requirement is that they are present in the environment when the process
starts.

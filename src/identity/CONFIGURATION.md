# RAMP Identity Service — Configuration Reference

This document lists every setting the Identity Service understands, what each one
does, and what happens if you leave it out. It is a reference, not a procedure — for
the step-by-step install see [`DEPLOYMENT.md`](DEPLOYMENT.md), and for day-to-day
operation see [`RUNBOOK.md`](RUNBOOK.md).

Audience: the DevOps engineer deploying the Identity Service. You do not need to read
the source code. Words that may be new are explained the first time they appear.

---

## 1. What the Identity Service needs to run

The Identity Service is a single Go binary in a container. It does two jobs: it is
the **keeper of every agent's private key**, and it is the **MCP endpoint** an AI
agent connects to in order to use RAMP. ("MCP" is the Model Context Protocol, the way
agent software discovers and calls tools.)

| Dependency | Required? | Why |
|---|---|---|
| PostgreSQL | **Yes** | Its own database, separate from the Exchange's. Holds agent cards, revocations, developer accounts and the OAuth records. The binary exits if it cannot reach it. |
| HashiCorp Vault | **Yes** | The only place agent private keys are stored. See [`deploy/storage/vault/`](../../deploy/storage/vault/CONFIGURATION.md), and §4 below for the one surprise. |
| An OIDC provider | **Yes** | OIDC is OpenID Connect, the standard way one service hands sign-in to another. This is where developers actually sign in. The binary exits if it cannot reach it at start-up. See [`deploy/zitadel/`](../../deploy/zitadel/CONFIGURATION.md). |
| A Broker and an Exchange address | **Yes** | Where agent tool calls are sent. Only the addresses are needed at start-up; neither has to be answering yet. |
| Outbound HTTPS to publishers' delivery addresses | Yes, at runtime | When an agent buys content, this service fetches the licensed content itself from the address the Exchange's answer names, and returns it inside the tool result. Those addresses are not known in advance, so the service needs general outbound HTTPS, not a fixed allow-list. |
| A wildcard DNS record and a matching wildcard TLS certificate | Yes, at runtime | Every agent gets its own subdomain, and other parties fetch its public key from there. See §3. |

It listens on **one port, `:8083`**. There is no admin port and no second listener.

Four things are worth knowing before you start, because operators often look for them
and they do not exist:

- **There are no command-line flags.** Configuration is 100% environment variables.
  The binary does accept one argument: `healthcheck`, which probes the service's own
  `/healthz` and exits. It exists so a container health check can run the binary
  itself — the image has no shell or `curl` to probe with.
- **There is no `LOG_LEVEL`.** The service always writes structured JSON logs at
  `INFO` level to standard output. ("Structured" means each log line is
  machine-readable data, not free text.)
- **There is no `/metrics` endpoint** and no Prometheus support. Alerting is done on
  log events — see [`RUNBOOK.md`](RUNBOOK.md) §2.2.
- **There is no switch to turn the MCP endpoint off.** See §2.

---

## 2. Environment variables

"Required" means the service will not start without it. Everything else has a
default, but several of the defaults are **not** safe for production — those are
called out below and in §6.

**The Vault variables are the one place where that test misleads you**, and they are
marked accordingly: the service starts happily without them and then fails every key
operation. §4 explains why.

Durations are written in Go's format — `30s`, `5m`, `24h`, `2160h`. **Days are not a
unit**: `90d` does not parse. A duration that does not parse is replaced by the
default **silently**, with nothing logged, so check your spelling against the
defaults below. The two byte-size settings (`IDENTITY_MCP_MAX_CONTENT_BYTES` and
`IDENTITY_MCP_MAX_CALL_CONTENT_BYTES`) behave differently on purpose: a value that
is not a positive whole number **stops start-up** with an error naming the
variable, and a value above the built-in ceiling is reduced to the ceiling rather
than replaced by the default.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `IDENTITY_DSN` | **Required** | The PostgreSQL connection string. Its own database — do not point it at the Exchange's. The service exits immediately if this is unset or unreachable. | `postgres://ramp:PASSWORD@db.internal:5432/identity?sslmode=require` |
| `IDENTITY_AUTH_ISSUER` | **Required** | This service's own public address, used as its OAuth issuer identity. It decides far more than it looks like — read the warning below. | `https://id.example` |
| `IDENTITY_OIDC_ISSUER` | **Required** | The address of the OIDC provider developers sign in against. The service contacts it **at start-up** and exits if it cannot. | `https://login.example` |
| `IDENTITY_OIDC_CLIENT_ID` | **Required** (or the `_FILE` form) | The client id your OIDC provider issued for this service. | `ramp-identity` |
| `IDENTITY_OIDC_CLIENT_ID_FILE` | Alternative to the inline form | Path to a file holding the same value, for deployments that mount secrets as files. Only read when the inline variable is empty. A file that is set but unreadable stops start-up — it is not treated as "not configured". | `/secrets/oidc_client_id` |
| `IDENTITY_OIDC_CLIENT_SECRET` | **Required** (or the `_FILE` form) | The matching client secret. | `<secret>` |
| `IDENTITY_OIDC_CLIENT_SECRET_FILE` | Alternative to the inline form | As above. | `/secrets/oidc_client_secret` |
| `IDENTITY_MCP_BROKER_URL` | **Required** | The Broker that agent discovery and purchases are relayed to. | `https://broker.example` |
| `IDENTITY_MCP_EXCHANGE_URL` | **Required** | The Exchange that holds agents' accounts, used by the account tools. | `https://exchange.example` |
| `VAULT_ADDR` | Optional, **set it** | The address of Vault. Read by the Vault client library, not by this service, so an unset value silently defaults to `https://127.0.0.1:8200` — see §4. | `https://vault.internal:8200` |
| `VAULT_TOKEN` | Optional, **set it** | The Vault token this service authenticates with. A token is the only authentication method implemented. | `<token>` |
| `IDENTITY_KV_MOUNT` | Optional | Which Vault secrets engine holds the keys. Default `secret`. | `ramp-agents` |
| `IDENTITY_KV_PREFIX` | Optional | The folder inside that engine. Default `agents`. Lets Vault hold unrelated secrets alongside without colliding. | `agents` |
| `IDENTITY_ADDR` | Optional | The address the service listens on. Default `:8083`. The container image publishes port 8083, so if you change this you must change the published port too. | `:8083` |
| `IDENTITY_BASE_DOMAIN` | Optional, **set it** | The identity zone — every agent gets a subdomain of it. Default **`rampmcp.org`**, which is almost certainly not yours. See §3. | `agents.example` |
| `IDENTITY_SESSION_KEY` | Optional, **set it** | Encrypts the browser cookies used during sign-up, as 32 bytes in standard base64. Created automatically when unset — see below. | `<44-character base64 string>` |
| `IDENTITY_TOKEN_SIGNING_KEY` | Optional, **set it** | Signs the access tokens agents present to the MCP endpoint, as a 32-byte Ed25519 seed in standard base64. Created automatically when unset — see below. | `<44-character base64 string>` |
| `IDENTITY_TOKEN_AUDIENCE` | Optional | What those tokens are valid for, and what the MCP endpoint advertises as its own identifier. Defaults to `IDENTITY_AUTH_ISSUER`, which is correct for a single deployment. Leave it alone unless you know why you are changing it. | *(leave unset)* |
| `IDENTITY_DIRECTORY_TTL` | Optional | How long a published document may be cached before it is rebuilt, and the `max-age` the service advertises to caches. Default `5m`. It bounds how quickly **this service's own** published documents reflect a change such as a revocation. The Broker and the Exchange add their own refresh delay on top, which this setting does not control — [`RUNBOOK.md`](RUNBOOK.md) §4.2 has the full timing. | `5m` |
| `IDENTITY_WELLKNOWN_SCHEME` | Optional | Which protocol appears in the addresses this service publishes about itself. Default `https`. **Must stay `https` in production.** | `https` |
| `IDENTITY_OIDC_SCOPES` | Optional | What the service asks the OIDC provider for, space-separated. Default `openid profile email`. | `openid profile email` |
| `IDENTITY_MCP_WELLKNOWN_SCHEME` | Optional | The protocol used when looking up an Exchange named in an offer. Falls back to `IDENTITY_WELLKNOWN_SCHEME`, then `https`. Leave unset. | *(leave unset)* |
| `IDENTITY_MCP_CALL_TIMEOUT` | Optional | How long one outbound call to the Broker or an Exchange may take. Default `30s`. | `30s` |
| `IDENTITY_MCP_SIGNATURE_TTL` | Optional | How long the signature on one of those calls stays valid. Default `30s`. Raising it widens the window in which a captured request could be replayed. | `30s` |
| `IDENTITY_MCP_POP_TTL` | Optional | How long the proof of possession on a content fetch stays valid. When an agent buys content, this service fetches it from the publisher's delivery address, proving it holds the agent's key. Default `30s`. It is a separate setting from `IDENTITY_MCP_SIGNATURE_TTL` on purpose: the delivery edge keeps no record of past requests, so this value is the window in which a captured fetch could be replayed — raising the RAMP signature lifetime for a slow peer must not widen it by accident. | `30s` |
| `IDENTITY_MCP_FETCH_TIMEOUT` | Optional | How long one content fetch from a publisher's delivery address may take, including reading the agent's key from Vault. Default `30s`. | `30s` |
| `IDENTITY_MCP_MAX_CONTENT_BYTES` | Optional | The largest single content body the service accepts, in bytes. Default `8388608` (8 MiB). A larger body is reported to the agent as a failure with the delivery link intact — never cut short and delivered incomplete. Values above 1 GiB are reduced to 1 GiB. Must not exceed `IDENTITY_MCP_MAX_CALL_CONTENT_BYTES` — that pair stops start-up. | `8388608` |
| `IDENTITY_MCP_CALL_CONTENT_TIMEOUT` | Optional | How long one `ramp_execute` call may spend fetching content in total, across all its items. Default `2m`. Items the call ran out of time for are reported as failures with their links intact, so the agent can fetch them in a later call. | `2m` |
| `IDENTITY_MCP_MAX_CALL_CONTENT_BYTES` | Optional | The most content one `ramp_execute` call may accumulate across all its items, in bytes. Default `33554432` (32 MiB). If you raise the per-item cap above, raise this with it — otherwise every batch collapses to one item, and the service refuses to start on a pair where the per-item cap is the larger. Values above 4 GiB are reduced to 4 GiB. | `33554432` |
| `IDENTITY_ROTATION_PERIOD` | Optional | How old an agent's key may get before it is replaced automatically. Default `2160h` (90 days). | `2160h` |
| `IDENTITY_ROTATION_OVERLAP` | Optional | How long the outgoing key keeps working after a replacement is created. Default `24h`. | `24h` |
| `IDENTITY_ROTATION_INTERVAL` | Optional | How often the service checks whether any agent is due. Default `1h`. | `1h` |
| `SKIP_SSRF` | Optional — **leave unset** | Setting this to `true` removes the guard that stops the service being tricked into calling internal addresses. Development only. | *(leave unset)* |
| `ALLOW_INSECURE` | Optional — **leave unset** | Setting this to `true` allows plain unencrypted `http` for those same calls. Development only. | *(leave unset)* |

### The two keys that generate themselves

`IDENTITY_SESSION_KEY` and `IDENTITY_TOKEN_SIGNING_KEY` do **not** stop the service
starting. The service creates each one itself instead, and each logs one warning:

```
{"level":"WARN","msg":"identity.signup.ephemeral_session_key","detail":"IDENTITY_SESSION_KEY unset; generated an ephemeral key (in-flight sign-ups drop on restart)"}
{"level":"WARN","msg":"identity.signup.ephemeral_token_key","detail":"IDENTITY_TOKEN_SIGNING_KEY unset; generated an ephemeral key (issued tokens invalid after restart)"}
```

The session key is the milder one: a restart interrupts sign-ups that are halfway
through, and nothing else.

**The token signing key is not mild.** It signs the access tokens agents present to
the MCP endpoint, *and* it is what verifies them. Invent a new one at every restart
and **every token ever issued stops working the moment the service restarts** — every
agent is signed out at once, with no warning to them and nothing in your logs
connecting the two events. Set it in any deployment that is not a throwaway.

Both are read as base64 and must decode to exactly 32 bytes. A wrong length is a
start-up failure, not a warning:

```
{"level":"ERROR","msg":"identity.exit","err":"sign-up config: IDENTITY_SESSION_KEY must decode to 32 bytes, got 5"}
```

> **These use standard base64, not the URL-safe form.** The Broker's
> `BROKER_ED25519_SEED` is URL-safe and 43 characters; these two are standard and 44
> characters, ending in `=`. They are not interchangeable, and the generation commands
> differ — [`DEPLOYMENT.md`](DEPLOYMENT.md) §7 has both.

### The MCP endpoint has no off switch

`IDENTITY_MCP_BROKER_URL` and `IDENTITY_MCP_EXCHANGE_URL` are both required and there
is no flag to disable the endpoint. Naming neither, or only one, stops start-up:

```
{"level":"ERROR","msg":"identity.exit","err":"mcp config: both IDENTITY_MCP_BROKER_URL and IDENTITY_MCP_EXCHANGE_URL are required (broker set: false, exchange set: false)"}
```

This is deliberate. The MCP endpoint is the only way an agent uses this service, so a
deployment that could not be told where to send agent traffic is not a working
deployment, and coming up in that state would look healthy while serving nobody.

### `IDENTITY_AUTH_ISSUER` decides more than its name suggests

It is not just a label. Everything below is derived from it:

- Every address the service advertises to agent software — the sign-in, token and
  registration endpoints in its published discovery document.
- **The redirect address your OIDC provider must have on file**, which is exactly
  `IDENTITY_AUTH_ISSUER` + `/callback`. If the two disagree by even a trailing slash,
  sign-in fails at the provider with a redirect-URI error.
- What access tokens are valid for, unless `IDENTITY_TOKEN_AUDIENCE` overrides it.
- Whether sign-up cookies are marked secure — that switches on automatically when the
  value starts with `https://`.

Set it to the public HTTPS address of this service and do not change it without good
reason: changing it means re-registering the client with your OIDC provider
([`deploy/zitadel/RUNBOOK.md`](../../deploy/zitadel/RUNBOOK.md) §3).

---

## 3. The identity zone

Every agent that signs up is given its own subdomain of `IDENTITY_BASE_DOMAIN` — for
example `agent-ovx4iigs.agents.example`. That subdomain is the agent's public
identity: the Broker and the Exchange fetch its public key from there in order to
check that a request really came from it.

Three consequences:

- **You need one wildcard DNS record** (`*.agents.example`) and **one matching
  wildcard TLS certificate**. Agents are created by developers signing themselves up,
  so there is no moment at which an operator could add a record by hand.
- **The zone must be reachable from the public internet over HTTPS.** The Broker and
  the Exchange fetch these documents themselves, from wherever they run.
- **Exactly one label is allowed.** `agent-x.agents.example` works;
  `a.b.agents.example` and the bare `agents.example` both return `404`.
  That matches what a wildcard certificate actually covers.

The default is **`rampmcp.org`**, which is a development value. A deployment left on
the default publishes agent addresses in a domain it does not control, and every
signature check against them fails.

---

## 4. Key storage — and the one surprise

Agent private keys live in Vault, at `<mount>/<prefix>/<subdomain>/<key>`. Nothing
else stores them, and there is no local or file-based alternative — a local key store
is **not implemented yet**.

**Vault is not contacted at start-up.** The service builds its Vault client and
carries on without checking that it works, so:

- A wrong `VAULT_ADDR`, a missing `VAULT_TOKEN`, an expired token or a sealed Vault
  all produce a service that **starts normally and reports healthy**.
- The failure appears later, per request: an agent's published documents return `503`
  and no new agent can be created.

This is the single most misread failure on this service. `/healthz` will not tell you
— see [`RUNBOOK.md`](RUNBOOK.md) §2.1.

The token needs a narrow policy, not root. The exact policy, the mount setup and what
you must back up are in
[`deploy/storage/vault/CONFIGURATION.md`](../../deploy/storage/vault/CONFIGURATION.md).

---

## 5. Putting TLS in front of it

**The Identity Service can sit behind a proxy that terminates HTTPS, and needs no
special setting for it.** If you have read the Broker's configuration document, this
is the question you are about to ask, and the answer is simpler here.

The Exchange and the Broker *verify* signatures over the request URL, so behind a
proxy that changes `https` to `http` they need `RAMP_TRUST_PROXY_HEADERS=true` to
recover the original scheme (§4 of each of their configuration documents explains
the conditions). The Identity Service verifies no such signatures — the documents it
publishes are public, and the MCP endpoint is protected by a token rather than a
signature. It only ever *makes* signed requests, never checks them, so there is no
flag to set here.

What does matter: whatever sits in front must serve the whole wildcard zone on a
certificate that covers it, and must pass the `Host` header through unchanged. The
service picks the agent out of the `Host` header, so a proxy that rewrites it makes
every agent's documents disappear behind a `404`.

---

## 6. Development defaults you must not copy

The compose files in this repository exist to run automated tests on a private
network. Several of their settings are deliberately unsafe:

| Setting | Why it is there | Why it must not ship |
|---|---|---|
| `IDENTITY_WELLKNOWN_SCHEME: "http"` | The test network has no certificates. | Agent identities would be published as `http` addresses, and every party that fetches them would do so unencrypted. |
| `SKIP_SSRF: "true"` | Test services live on private addresses the guard blocks. | Removes the protection against the service being steered into your internal network. |
| `ALLOW_INSECURE: "true"` | Same reason. | Same consequence. |
| `sslmode=disable` in the DSN | The database is on the same private bridge. | Database traffic, including credentials, in the clear. |
| `VAULT_TOKEN: "root"` against a `-dev` Vault | The test Vault starts unsealed with a fixed token and no storage. | It keeps nothing across a restart and grants unlimited access. Every agent key in it would be lost on restart and readable by anyone who reached it. |
| `IDENTITY_TOKEN_SIGNING_KEY: "AAAA…"` | A fixed value so tests can create their own tokens. | It is published in this repository. Anyone could sign a token that this service accepts as any agent. |
| `IDENTITY_BASE_DOMAIN: "rampmcp.org"` | The zone the test stack resolves internally. | Not a domain you control. |
| `user: "0"` and `IDENTITY_ADDR: ":80"` | The test stack needs the agent subdomains on the default port. | Runs the service as root for no benefit; put a proxy in front instead. |

---

## 7. Worked example

Values marked *fill in* are specific to your environment.

```
IDENTITY_DSN=postgres://ramp:<password>@<db-host>:5432/identity?sslmode=require
IDENTITY_ADDR=:8083
IDENTITY_BASE_DOMAIN=agents.example
IDENTITY_AUTH_ISSUER=https://id.example
IDENTITY_OIDC_ISSUER=https://login.example
IDENTITY_OIDC_CLIENT_ID_FILE=/secrets/oidc_client_id
IDENTITY_OIDC_CLIENT_SECRET_FILE=/secrets/oidc_client_secret
IDENTITY_SESSION_KEY=<fill in — see DEPLOYMENT.md §7>
IDENTITY_TOKEN_SIGNING_KEY=<fill in — see DEPLOYMENT.md §7>
IDENTITY_MCP_BROKER_URL=https://broker.example
IDENTITY_MCP_EXCHANGE_URL=https://exchange.example
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN=<fill in — see deploy/storage/vault/DEPLOYMENT.md §5>
IDENTITY_KV_MOUNT=ramp-agents
IDENTITY_KV_PREFIX=agents
```

Everything not listed is left at its default. In particular `SKIP_SSRF` and
`ALLOW_INSECURE` stay unset, `IDENTITY_WELLKNOWN_SCHEME` stays at its `https` default,
and the three `IDENTITY_ROTATION_*` settings stay at 90 days / 24 hours / 1 hour.

The secret values above (`IDENTITY_DSN`, the two OIDC credentials, the two keys and
`VAULT_TOKEN`) are read as plain environment variables, or as files for the two that
have a `_FILE` form. The service does not know or care where they came from, so the
secret store and the tooling that supplies them are your choice — the only requirement
is that they are present when the process starts.

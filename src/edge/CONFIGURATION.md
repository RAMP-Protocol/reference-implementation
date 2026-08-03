# RAMP Edge Worker — Configuration Reference

This document lists every setting the Worker understands, what each one does, and
what happens if you leave it out. It is a reference, not a procedure — for the
step-by-step install see [`DEPLOYMENT.md`](DEPLOYMENT.md), and for day-to-day
operation see [`RUNBOOK.md`](RUNBOOK.md).

Audience: you, the DevOps engineer deploying the Worker. You do not need to read
the source code. Words that may be new are explained the first time they appear.

---

## 1. What the Worker needs to run

The Worker is one small program that Cloudflare runs at its edge, in front of the
publisher's article pages. It needs:

| Dependency | Required? | Why |
|---|---|---|
| A Cloudflare zone with proxied DNS | **Yes** | A "zone" is a domain in Cloudflare. The Worker only runs on proxied traffic. |
| A reachable origin | **Yes** | The real backend holding the article pages. Reached either through the zone (`SAME_ZONE_ORIGIN`) or at an explicit address (`ORIGIN_URL`) — §3.1. |
| The Exchange's key directory | Yes, at runtime | Fetched over the public internet to get the public keys that signed URLs are checked against (`EXCHANGE_WBA_URL`). |

Before you start, note six things that operators often look for; most of them
do not exist here:

- **There are no secrets.** Every value below is public configuration — no
  password, no private key. So you do not need `wrangler secret`, a secret store,
  or an encrypted variable; plain Cloudflare `vars` are enough. (The private
  signing key stays inside the Exchange and is never given to Cloudflare or to the
  publisher.)
- **There are no command-line flags.** Configuration is 100% environment
  variables — in Cloudflare these are called "vars".
- **There is no `LOG_LEVEL`.** The Worker writes structured records (machine-
  readable data, not free text) to Workers Logs, at two levels only: `warn` for
  expected denials, `error` for operational failures.
- **There is no `/metrics` endpoint** and no Prometheus support. Alerting is done
  on log events — see [`RUNBOOK.md`](RUNBOOK.md) §2.3.
- **The Worker is stateless** and needs **zero bindings**. (A "binding" is a
  connection from a Worker to a Cloudflare storage product.) No KV, no D1, no R2,
  no Durable Objects, no Queues.
- **`RAMP_ENFORCE_BINDING` defaults to on.** ("Binding" here means a second
  thing: a delivery address tied to one agent.) The Worker requires
  cryptographic proof that the caller holds the key the address was issued
  to — §3.6.

---

## 2. Environment variables

"Required" means the Worker refuses to start without it. A missing required
variable is not a partial failure: the Worker fails with an error on **every**
request.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `EXCHANGE_URL` | **Required** | Base address of the Exchange. Its **only** runtime effect is the `X-RAMP-Exchange` header on a bot denial — a hint telling the bot where to negotiate. The Worker never calls this address. | `https://exchange.example` |
| `EXCHANGE_WBA_URL` | **Required** | The Exchange's public-key directory. This is the address the Worker actually fetches, to get the keys that verify signed URLs. | `https://exchange.example/.well-known/http-message-signatures-directory` |
| `PROVIDER` | **Required** | The publisher's identifier, usually its domain. Published as the `domain` field of the discovery document. | `www.publisher.example` |
| `EXCHANGES_JSON` | **Required** | JSON list of the Exchanges that represent this publisher, published in the discovery document. **Read §3.5 before writing this** — it carries the payee id. | see §3.5 |
| `SAME_ZONE_ORIGIN` | One of the two, see §3.1 | `"true"` forwards to the zone's own configured origin. Cloudflare-only. | `true` |
| `ORIGIN_URL` | One of the two, see §3.1 | Explicit address of a dedicated backend. | `https://origin.publisher.example` |
| `RAMP_VERIFY_KEYS` | Optional | JSON list of public keys to pin, skipping the network fetch — §3.2. | `[{"kty":"OKP","crv":"Ed25519","x":"<43-char base64url>"}]` |
| `WBA_KEYS_JSON` | Optional | JSON list of the **publisher's own** public signing keys, served in its key directory. Unset is a legitimate configuration — §3.4. | see §3.4 |
| `WBA_REVOCATION_URL` | Optional | Address where verifiers check whether the publisher's own keys were withdrawn. Ignored unless `WBA_KEYS_JSON` is also set. | `https://www.publisher.example/key-revocations` |
| `RSL_BODY` | Optional | Text served at `/rsl.txt` as a licensing hint. Unset serves an empty document, not a 404 — §3.4. | `# RSL hint` |
| `ACME_TOKENS_JSON` | Optional | JSON map of domain-verification tokens to their answers. Unset means every token address returns 404 — §3.4. | `{"token123":"challenge-response"}` |
| `CATALOG_CONTRIBUTORS_JSON` | Optional | JSON list of other parties allowed to add content on the publisher's behalf. Unset means only `PROVIDER` itself may. | `[{"domain":"partner.example.com","relationship":"licensee"}]` |
| `BOT_UA_ALLOW_JSON` | Optional | Replaces the built-in search-crawler list — §3.3. | `["Googlebot","bingbot"]` |
| `BOT_UA_DENY_JSON` | Optional | Replaces the built-in AI-bot list — §3.3. | `["GPTBot","ClaudeBot"]` |
| `RAMP_ENFORCE_BINDING` | Optional | `"false"` switches this Worker to the weaker mode, where a delivery address works for whoever holds it. Unset means the proof check runs — §3.6. | `true` |

All values are strings, including the ones that look like lists or booleans:
Cloudflare vars are text, and the Worker parses them. A JSON value that does not
parse, or does not match the expected shape, **intentionally fails at
start-up** — a malformed list must break the deploy, not silently disable a
check.

**A name the Worker does not know is ignored, not rejected.** The check is on
values, not on names: a variable outside the table above is simply ignored, so a
misspelled name behaves exactly like an unset one. Nothing at deploy time will
tell you. Manually compare the names you set against the table.

---

## 3. Settings that depend on each other

### 3.1 Origin mode — choose exactly one

"Origin" is the real backend server holding the website's pages. The Worker must
know how to reach it, and there are two ways.

| | `SAME_ZONE_ORIGIN="true"` | `ORIGIN_URL="https://…"` |
|---|---|---|
| **Choose when** | The zone already has an origin configured in Cloudflare — typically a shared load balancer that routes by `Host` (the name of the site being requested). | There is one dedicated backend address for this site alone. |
| **What the Worker does** | Re-fetches the incoming address with the signature parameters removed; Cloudflare routes that subrequest to the zone's origin, keeping the original `Host`. | Rewrites the request to that address, keeping path and query. The backend sees **its own** hostname in `Host`. |
| **Needs an address?** | No | Yes |
| **Works on** | Cloudflare only | Cloudflare, Fastly |
| **Common mistake** | Only works on a zone route, so `workers_dev` must be off — [`DEPLOYMENT.md`](DEPLOYMENT.md) §6.3. | The address must **not** resolve back to the Worker's own route, or requests loop forever. |

`SAME_ZONE_ORIGIN` is **Cloudflare-only**, by design: the Fastly adapter does
not forward the variable at all (so setting it there does nothing), and the AWS
Lambda@Edge adapter fails at start-up if it sees it, because forwarding to the
incoming address on CloudFront would make the function fetch its own distribution.

**Setting neither is the most common misconfiguration.** On Cloudflare the Worker
does not partly work — it fails on *every* request, with this message:

```
edge misconfigured: set ORIGIN_URL to the origin backend, or SAME_ZONE_ORIGIN="true" to forward to this zone's configured origin
```

This is deliberate. Without the guard, every verified request would get an empty
`200` — a deployment that looks healthy while delivering nothing.

### 3.2 `RAMP_VERIFY_KEYS` — pinning, and why rotation still works

By default the Worker fetches the Exchange's public keys from `EXCHANGE_WBA_URL`
and caches them. Setting `RAMP_VERIFY_KEYS` to a JSON list of public keys pins
them instead: verification then runs with no network call at all.

Pinning does **not** stop you from rotating keys. When a signed URL names a key
id that is not in the pinned set, the Worker performs one directory fetch and
retries the lookup against what it finds. That single fetch is what makes a
rotation fix itself — pinning is a latency and availability optimisation, not a
fixed set.

The trade-off to be aware of: with keys pinned, an unreachable directory no
longer affects the keys you pinned, but a rotation you have not yet followed
still needs the directory to be reachable at the moment the new key first appears.

### 3.3 The bot lists — what they are, and what replaces them

On an unsigned `GET`/`HEAD` the Worker sorts the caller into human (pass through),
search crawler (pass through, free — the publisher wants indexing) or AI bot
(`403` plus instructions on how to buy). Cloudflare's own verified-bot data is
consulted first where available; the two pattern lists below are the fallback,
and most deployments rely only on these lists.

**Built-in search-crawler allow list** (matched case-insensitively, first):

```
Googlebot        bingbot        DuckDuckBot        Applebot(?!-Extended)        YandexBot
```

The `Applebot(?!-Extended)` pattern deliberately excludes `Applebot-Extended`,
Apple's AI crawler, which is still blocked and must pay.

**Built-in AI-bot deny list** (matched after the allow list):

```
bot\b        crawler        spider        GPTBot        ClaudeBot        anthropic-ai
OAI-SearchBot        CCBot        PerplexityBot        Bytespider        Google-Extended
```

A caller sending **no** identity string at all counts as a bot — normal browsers
always send one. Anything matching neither list is a human.

`BOT_UA_ALLOW_JSON` and `BOT_UA_DENY_JSON` **replace** the corresponding built-in
list entirely — they do not extend it. If you set one, include again the
built-in entries you still want. Each is a JSON array of regular-expression patterns, with
hard limits:

| Limit | Value | If exceeded |
|---|---|---|
| Entries per list | at most 64 | Start-up fails |
| Characters per entry | at most 256 | Start-up fails |
| Pattern validity | must compile as a regular expression | Start-up fails |

The start-up failure on an invalid pattern is deliberate: a broken pattern list
must fail the deploy, never silently disable the bot gate. Keep patterns to simple
name fragments like the built-ins — the size caps limit how much text is scanned,
but they cannot save you from a badly written pattern such as `(a+)+`, which can
take a very long time to run.

### 3.4 The optional documents — what "unset" actually serves

Four addresses the Worker answers itself. Three of them behave differently when
their variable is unset, and the differences are easy to mistake for errors.

| Address | Variable | Set | Unset |
|---|---|---|---|
| `/.well-known/ramp.json` | `PROVIDER`, `EXCHANGES_JSON` | The discovery document | Cannot happen — both are required |
| `/.well-known/http-message-signatures-directory` | `WBA_KEYS_JSON` | The publisher's public keys, as a JWK Set | **404** |
| `/rsl.txt` | `RSL_BODY` | The text you supplied | **200 with an empty body** — not a 404 |
| `/.well-known/ramp-verify/<token>` | `ACME_TOKENS_JSON` | The answer for a known token; 404 for any other | **404 for every token** |

**A 404 on the key directory is a legitimate configuration, not a fault.** That
directory publishes the *publisher's own* signing keys, and a publisher that
issues none has nothing to publish. It is unrelated to the keys the Worker uses to
check signed URLs — those come from the *Exchange's* directory at
`EXCHANGE_WBA_URL` and are never served here.

Note that `/rsl.txt` sits at the top level, not under `/.well-known/`, and that
all four addresses are answered by the Worker rather than passed to the origin. If
the site already publishes its own document at one of these addresses, the Worker
answers instead of the site.

### 3.5 `EXCHANGES_JSON` — and the payee id inside it

Each entry in the list takes this shape:

| Field | Required? | What it is |
|---|---|---|
| `domain` | **Yes** | The Exchange's own canonical domain. Must match **exactly** what the Exchange calls itself, or the payee lookup below finds nothing. |
| `endpoint` | **Yes** | Full address of the Exchange. |
| `supported_profiles` | Optional | List of profile names; defaults to empty. |
| `ext` | **Effectively required** | Extension map. Carries `resource_owner_id`. |

**`ext.resource_owner_id` is the publisher's payee id — the account that
receives the payments for the content.** The Exchange reads it out of the
discovery document this Worker serves, matching on the entry whose `domain`
equals the Exchange's own. The Worker never computes this value itself, and
there is no default:

> **Without it, every catalog push for this publisher is rejected**, with the
> reason `missing_resource_owner_id`. The publisher's content never enters the
> catalog, so nothing about it can ever be sold — while the Worker itself looks
> perfectly healthy and serves the discovery document without complaint.

A complete entry:

```json
[{"domain":"exchange.example",
  "endpoint":"https://exchange.example",
  "supported_profiles":["ramp-news-v1"],
  "ext":{"resource_owner_id":"publisher-01"}}]
```

Two things to confirm with the Exchange operator before you deploy: the exact
`domain` string the Exchange identifies itself by, and the `resource_owner_id`
value to declare. Getting either wrong produces the same silent rejection.

---

### 3.6 `RAMP_ENFORCE_BINDING` — proof that the caller holds the key

A delivery address the Exchange ties to one agent carries that agent's key
fingerprint. With this check on, the Worker requires the caller to prove it holds
the matching private key, so an address that leaks is useless to whoever picked it
up. With it off, the address is a *bearer credential*: whoever holds it reads the
article until it expires, protected only by its short lifetime and HTTPS.

**Unset means on.** The rule is "enforce wherever the Worker can run the check",
so the safe mode needs no configuration. Set it to `"true"` anyway if you want
the choice visible in your own config; only `"true"` and `"false"` are accepted,
and any other value fails the deploy rather than choosing a mode for you.

Agents that sign up through a registry do not hold their own key — the registry
keeps it and fetches the content for them, so the registry is what proves
possession. Nothing is required of those agents for this check to pass.

**Deploy the registry before this Worker goes live with the check on.** A
registry that cannot yet present the key is refused, and every fetch through it
fails with `403`. If this Worker must be deployed first, set
`RAMP_ENFORCE_BINDING = "false"` and remove it once the registry is live. Treat
that period as a temporary, less secure state, not a setting to keep
permanently.

Publishers fronted by CloudFront alone cannot run this check at all — CloudFront
verifies the address itself and has nowhere to run the extra step. Those sites
keep the bearer mode, and this variable does not apply to them.

---

## 4. Non-configurable defaults you must still know

These are fixed in the code. No environment variable changes them; a different
value needs a code change and a redeploy.

| Behaviour | Value | Why it matters to you |
|---|---|---|
| Key-directory cache lifetime | **1 hour** | How long a stale key set can persist, and therefore how long a key-rotation problem takes to clear on its own. There is no variable for it. |
| Key-directory body size cap | 64 KiB | A larger response is rejected before parsing. |
| Keys per directory | at most 64 | A larger key set is rejected. |
| Caller identity string scanned | first **512** characters | The bot patterns are applied only to these characters. A marker after that point is never matched. |
| Reserved query parameters | `exp`, `sig`, `kid`, `agent_id` | Stripped before every forward to the origin. The site must not use these names for its own purposes. |
| `compatibility_date` | `2026-07-01` | The Cloudflare runtime version the code is developed against. Keep it aligned — see [`RUNBOOK.md`](RUNBOOK.md) §4.3. |
| `compatibility_flags` | `["nodejs_compat"]` | Required; the code relies on it. |
| Configuration read | once per isolate, then cached | An "isolate" is the small sandbox Cloudflare runs one copy of the Worker in. A variable change reaches traffic through a new deployment version, not through a live reload. |

---

## 5. The Exchange-side prerequisite

Configuring the Worker correctly is not sufficient on its own. **The publisher's
tenant must be set up on the Exchange with `signing_scheme = 'ED25519'`.**
That setting is what makes the Exchange sign delivery addresses in the form this
Worker verifies. With any other scheme the delivery address does not carry the
signature the Worker checks, and every paid request is refused.

This is an Exchange-side action, taken by the Exchange operator — see
[`../exchange/RUNBOOK.md`](../exchange/RUNBOOK.md). Confirm it is done before
running the signed-URL verification in [`DEPLOYMENT.md`](DEPLOYMENT.md) §8.

---

## 6. Development defaults you must not copy

The repository's compose files exist to run automated tests on a private Docker
network. Several of their values are deliberately unsuitable for production:

| Value seen in the test stack | Why it is there | Why it must not ship |
|---|---|---|
| `EXCHANGE_URL: "http://exchange:8081"` | Container-to-container names on a private bridge. | Unencrypted, and the hostname resolves nowhere on the internet. |
| `EXCHANGE_WBA_URL: "http://…"` | Same. | Public keys fetched over unencrypted HTTP could be modified in transit. |
| `ORIGIN_URL: "http://publisher:80"` | Same. | Same. |
| `EXCHANGES_JSON` with `"domain":"exchange:8081"` | Matches the test Exchange's own identity, which is a container name and port. | A real deployment's `domain` is a real hostname — §3.5. |
| `WBA_KEYS_JSON` from `deploy/edge-keys/edge.env` | Generated test keys whose private keys are stored in the repository. | Generate the publisher's own keys, or leave the variable unset. |

The commented-out `[vars]` block at the top of `wrangler.toml` is likewise an
example with `example.com` placeholders, not a starting configuration.

---

## 7. Complete example — staging values

The `[env.staging]` block in `wrangler.toml` is a real, working example. Values
marked *fill in* are specific to your deployment.

| Variable | Staging value |
|---|---|
| `EXCHANGE_URL` | `https://exchange.example` |
| `EXCHANGE_WBA_URL` | `https://exchange.example/.well-known/http-message-signatures-directory` |
| `PROVIDER` | `www.publisher.example` |
| `EXCHANGES_JSON` | `[{"domain":"<the Exchange's own domain — fill in>","endpoint":"https://exchange.example","supported_profiles":[],"ext":{"resource_owner_id":"<fill in>"}}]` |
| `SAME_ZONE_ORIGIN` | `true` |

Worker settings, the same for every environment:

| Setting | Value |
|---|---|
| Worker name | `ramp-edge` (staging uses `ramp-edge-staging`) |
| Entry point | `src/entries/cloudflare.ts` |
| `compatibility_date` | `2026-07-01` |
| `compatibility_flags` | `["nodejs_compat"]` |
| `workers_dev` | `false` |
| Observability | enabled, `head_sampling_rate = 1` |
| Bindings | none |

Everything not listed stays unset. In particular `RAMP_VERIFY_KEYS`,
`WBA_KEYS_JSON`, `ACME_TOKENS_JSON`, `BOT_UA_ALLOW_JSON`, `BOT_UA_DENY_JSON`
and `RAMP_ENFORCE_BINDING` are absent, which is the intended default in every
case (unset `RAMP_ENFORCE_BINDING` means the proof check runs — §3.6). A name
that is not in the §2 table is not read at all, set or unset.

The `ext.resource_owner_id` field is **not** in the checked-in staging block and
must be added before the publisher's content can be sold — §3.5.

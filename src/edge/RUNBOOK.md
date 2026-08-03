# RAMP Edge Worker — Runbook

Operated by the Publisher.

**Escalation.** If §3 does not resolve it, contact Postindustria at
`<support channel — fill in before handover>`. Send the `request_id` of a failing
request together with the matching Workers Logs records and, where the Exchange is
involved, its log lines for the same `request_id`. Postindustria has no access to
your Cloudflare account, so that correlation ID is the only way a request can be
traced across the two services.

> This runbook assumes the Worker is already deployed. For installation,
> configuration values and deploy-time verification, see
> [`DEPLOYMENT.md`](DEPLOYMENT.md) and [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

One article address serves four kinds of caller: a human with a browser, a search
crawler, an AI bot that has not paid, and an AI agent that has. There is no
separate paid link, so **this Worker is the only gate** — every one of those
decisions is made here, in front of the origin.

```
human            ──► 200, the article
search crawler   ──► 200, the article (free — the publisher wants indexing)
unpaid AI bot    ──► 403 + where to buy access
paying agent     ──► signature checked ──► 200, the article
```

Who owns what:

| | Publisher (you) | Exchange operator |
|---|---|---|
| Owns | The Cloudflare zone, the Worker, the origin, the DNS records | Pricing, the signing keys, settlement, the catalog |
| Changes by | Deploying this Worker, editing zone settings | Operating the Exchange |

Who to contact for which symptom:

| Symptom | Owner |
|---|---|
| Visitors get errors; `502`s | You — the origin or its address (§3.1) |
| Bots are not reaching the Worker at all | You — zone security or routes (§3.3) |
| Paying agents refused although the address looks valid | Exchange operator — keys or clock (§3.1) |
| The publisher's content is not on sale at all | Exchange operator — the payee declaration ([`CONFIGURATION.md`](CONFIGURATION.md) §3.5) |
| Prices, offers, settlement | Exchange operator |

---

## 2. Monitoring

### 2.1 Health

**There is no health endpoint for article traffic.** The Worker answers
`/healthz` with `ok`, but that only proves an isolate started — an isolate is the
small sandbox Cloudflare runs one copy of the Worker in. It says nothing about
the origin, the Exchange's keys, or whether the routes are attached. (It also
answers instead of any `/healthz` the origin itself publishes.)

The Worker is stateless, so health is observed from traffic. The four deployment
checks also work as a health check; run them on a schedule against a real
article:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -A "Mozilla/5.0" https://<host>/some-article-path
# Expect: 200

curl -s -o /dev/null -w '%{http_code}\n' -A "GPTBot/1.0" https://<host>/some-article-path
# Expect: 403

curl -s -o /dev/null -w '%{http_code}\n' https://<host>/.well-known/ramp.json
# Expect: 200

curl -s -o /dev/null -w '%{http_code}\n' "https://<host>/some-article-path?exp=…&sig=…&kid=…"
# Expect: 200 (needs a fresh signed address from the Exchange)
```

Also confirm Workers Logs is still retaining records: open the Worker's Logs view
in the Cloudflare dashboard and check that recent `edge.*` records are present.
This is a dashboard toggle and Terraform cannot enable it
([`DEPLOYMENT.md`](DEPLOYMENT.md) §9), so it is worth re-checking after any change
to how the Worker is deployed.

### 2.2 Logs

The Worker writes structured records to Workers Logs. **Only denials and failures
produce one** — a request that is served writes no `edge.*` record at all.
Cloudflare's own invocation log still shows the request.

| Event | Level | Means |
|---|---|---|
| `edge.origin.fetch_failed` | ERROR | The origin could not be reached. The caller got a `502`. Carries `message`. |
| `edge.keys.load_failed` | ERROR | The Exchange's key directory is unreachable or unreadable. Carries `message` and `wba_url`. |
| `edge.verify.unavailable` | ERROR | A signature could not be checked because key loading failed. The caller got a retryable `503`. |
| `edge.deny.bot` | WARN | An unpaid AI bot was sent to negotiate. `reason=ai_bot`. |
| `edge.deny.signature` | WARN | A signature was invalid or expired. Carries `reason`, and `kid` when one was resolved. |
| `edge.deny.binding` | WARN | A caller failed to prove it holds the key its delivery address was issued to. Carries `reason` — see §3.1 for what each value means. Expected traffic on a Worker with the check on, which is the default. |
| `edge.deny.method` | WARN | A signed read address replayed with a write method. `reason=method_not_bound`. |

Every record carries `method`, `path` and `request_id` — **except
`edge.keys.load_failed`, which carries no `request_id` on purpose.** The key cache
is a single shared object with no request context, and one fetch serves many
requests at once, so naming any single request would be misleading. Use `wba_url`
to tie it to something instead. Expect it to appear alongside
`edge.verify.unavailable` records, which do carry request ids.

**A failed verification logs the reason but never the full address.** A signed
address can contain data an attacker chose, so only the reason and the public key
id are recorded. The URL is intentionally not logged, so do not search for it.

`X-Request-ID` ties the two services together: the Worker keeps an incoming one
and otherwise creates a new one, adds it to every record above, and returns it
on the responses it composes itself. Give the same value to the Exchange operator
to find the matching records on the Exchange side. (On an origin pass-through the response is
the origin's own; do not rely on the header being present there.)

### 2.3 Alerts

**These are recommendations, not configured alerts.** Nothing here ships an
alerting rule — the Worker has no metrics endpoint, so these are log conditions
for you to wire into whatever monitoring you already run.

| Signal | Severity | First action |
|---|---|---|
| `edge.origin.fetch_failed` | **Critical — page on-call immediately** | **Ordinary visitors are affected, not just agents** — the site is returning `502`s. Check the origin, then its address (§3.1). This is the row that matters most. |
| `edge.keys.load_failed` | **Critical — page on-call immediately** | Paying agents start being refused. The Exchange's key directory is down or malformed (§3.1). |
| `edge.verify.unavailable` | **Critical — page on-call immediately** | Signed requests are getting `503`s. Same cause as the row above; these two events usually appear together. |
| A **sudden increase** in `edge.deny.signature` | Business hours | Usually Exchange key rotation, or clock skew (clocks showing different times) between the Exchange and the caller. §3.1. |

**Never set an alert on `edge.deny.*` in general.** Those records are normal
behavior of the Worker — every unpaid bot produces one, and a busy site produces
many.
Only a sudden change in the `edge.deny.signature` rate is worth attention.

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| **A sudden wave of `403` responses** | Two different causes share this response code. Separate them first — see below how to distinguish them. | Read the `edge.deny.*` event name. |
| Clock skew, or an address presented too late | A signed address carries an expiry (`exp`). A caller whose clock is slow, or that waits too long before using the address, presents an expired one. | Look for `edge.deny.signature` with `reason=expired`. Check the caller's clock; the Worker cannot extend the expiry time. |
| The key directory is unreachable | Signed requests cannot be verified, so they are refused with a `503` rather than let through. | `edge.keys.load_failed` names the cause. **It fixes itself within the one-hour cache lifetime** once the directory answers again — that lifetime is fixed and no setting shortens it. Escalate to the Exchange operator. |
| Visitors get `502` | The origin is down, or its address is wrong. | `edge.origin.fetch_failed` carries the message. If `ORIGIN_URL` is in use, confirm it does **not** resolve back to the Worker's own route — that loops until Cloudflare cuts it off. |
| **Every** request fails after a deploy | Neither origin mode is set, so the Worker fails with an error before it can serve anything. | The error message names both variables. [`CONFIGURATION.md`](CONFIGURATION.md) §3.1. |
| Search crawlers are blocked | Cloudflare's WAF managed rules and bot products run **before** the Worker; a blocked crawler never reaches it. | Check Security Events for the crawler, add a skip rule. [`DEPLOYMENT.md`](DEPLOYMENT.md) §7. |
| AI bots never reach the Worker | Zone-level AI-bot blocking runs **before** the Worker, so the bot is refused without ever learning how to pay. | Turn off "Block AI bots" / Bot Fight Mode for the article paths. This loses money and does not add security. |
| The Worker is reachable on `*.workers.dev` | `workers_dev` was left on, so the zone — and therefore the gate — can be bypassed. | Set `workers_dev = false` and redeploy. [`DEPLOYMENT.md`](DEPLOYMENT.md) §6.3. |
| The publisher's content is not for sale | The discovery document carries no payee declaration, so every catalog push is rejected. | Check `ext.resource_owner_id` — [`CONFIGURATION.md`](CONFIGURATION.md) §3.5. |

**How to tell the two apart.** Read the event name in Workers Logs:

```
edge.deny.bot         → an unpaid AI bot. NORMAL. Rising volume means more
                        crawlers are finding the site, not that anything broke.

edge.deny.signature   → paying agents are being refused. Check `reason`:
                          expired  → clock skew, or a stale address (above)
                          anything else → key mismatch. Compare the `kid` in
                          the record against the key ids the Exchange publishes
                          (§3.2). Usually a rotation in progress.
```

**A third cause: `edge.deny.binding`.** That record reports a caller failing to
prove it holds the key its address was issued to — the check
`RAMP_ENFORCE_BINDING` governs, on by default. Read its `reason`:

```
missing_agent_key   → the caller presented no key at all. An agent fetching its
                      own address directly cannot pass this check when the key is
                      held by a registry; the registry is meant to fetch on
                      its behalf.
keyid_mismatch      → the caller proved a key, but not the one this address names.
thumbprint_mismatch → the key presented does not hash to the id it claims.
pop_expired         → the proof itself expired. Clock skew, or a caller reusing an
                      old proof.
pop_sig_invalid     → the signature over the request did not verify.
```

A wave of `missing_agent_key` records right after a deploy usually means this
Worker was deployed before the registry that fetches for its agents — see
[`CONFIGURATION.md`](CONFIGURATION.md) §3.6 for the rollout order and the
temporary `"false"` workaround, and treat that setting as a temporary, less
secure state.

### 3.2 Diagnostics

**Find the decision for one request.** In the Worker's Logs view, filter on the
correlation id:

```
request_id = "<the id from the X-Request-ID header>"
# Expect: at most one edge.* record. A served request produces none —
#         absence means the request was allowed, not that it was lost.
```

**Reproduce all four decision paths** against a real article:

```bash
curl -s -o /dev/null -w 'human            %{http_code}\n' \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://<host>/some-article-path
# Expect: human            200

curl -s -o /dev/null -w 'search crawler   %{http_code}\n' \
  -A "Googlebot/2.1" https://<host>/some-article-path
# Expect: search crawler   200

curl -s -o /dev/null -w 'unpaid AI bot    %{http_code}\n' \
  -A "GPTBot/1.0" https://<host>/some-article-path
# Expect: unpaid AI bot    403

curl -s -o /dev/null -w 'paying agent     %{http_code}\n' \
  "https://<host>/some-article-path?exp=…&sig=…&kid=…"
# Expect: paying agent     200
```

**Read the discovery documents the Worker is currently serving:**

```bash
curl -s https://<host>/.well-known/ramp.json
# Expect: "role":"ROLE_PUBLISHER", the publisher's domain, and an exchanges
#         entry carrying "ext":{"resource_owner_id":"…"}.

curl -s https://<host>/.well-known/http-message-signatures-directory
# Expect: a JWK Set of the publisher's OWN keys — or 404, which is legitimate
#         when the publisher issues none.
```

**Confirm which keys are in use.** The Worker checks signatures against the
Exchange's directory, not its own:

```bash
curl -s "$EXCHANGE_WBA_URL"
# Expect: {"keys":[{"kty":"OKP","crv":"Ed25519","x":"…"}, …]}
```

A `kid` in an `edge.deny.signature` record that does not correspond to any key
there is a sign that the Worker has not picked up a rotation yet — §4.2.

### 3.3 Gotchas

- **Routes must cover `/.well-known/*`.** Missing them breaks bot negotiation
  silently: the bot gets a `403` pointing at the discovery document, follows the
  pointer, and finds the origin's `404`.
- **A grey-cloud DNS record means the Worker never runs.** No error is logged
  anywhere — the gate is simply bypassed and everything is served free.
- **Zone security runs before the Worker.** WAF rules, Bot Fight Mode and AI-bot
  blocking can refuse a caller the Worker would have handled. If traffic is
  missing rather than denied, look there first.
- **The user-agent lists are an approximate filter, not a security barrier.** A
  scraper that pretends to be a browser still passes. Paid access is
  enforced only by the signed addresses; stealth-bot detection is Cloudflare's bot
  management product, not this Worker.
- **The Worker holds no KV or other storage**, so "cache purge" here only ever
  means the zone cache. There is nothing inside the Worker to clear.

---

## 4. Procedures

### 4.1 Routine operations

**Deploy a code change.** Rebuild and deploy; nothing else is needed.

```bash
cd src/edge && npm ci && npx wrangler deploy --env production
# Expect: "Uploaded ramp-edge (N sec)", "Deployed ramp-edge triggers (N sec)",
#         the route list, and a new "Current Version ID".
```

**Change configuration only.** Variables are not code. Edit the environment
block's vars in `wrangler.toml` and deploy the same way — the bundle is unchanged
but a new version is published, and new isolates use the new values. Note that
`wrangler deploy` **replaces** the Worker's vars with what the file says, so any
edit made in the dashboard is overwritten. Keep `wrangler.toml` as the single
authoritative configuration.

**Update the bot patterns.** `BOT_UA_ALLOW_JSON` and `BOT_UA_DENY_JSON` replace
the built-in lists rather than extending them, so include again the entries you
want to keep ([`CONFIGURATION.md`](CONFIGURATION.md) §3.3). An invalid pattern
intentionally fails the deploy. Verify afterwards with the four-path reproduction in §3.2.

**Cache purge.** Purging the zone cache is a Cloudflare operation and affects only
origin responses. It does not touch the Worker, which caches nothing except the
Exchange's public keys, in memory, for one hour.

**Verify the DNS records are still proxied** — after any DNS change, and after any
migration between accounts:

```bash
curl -sI https://<host>/ | grep -i '^server:'
# Expect: server: cloudflare
```

### 4.2 Publisher and key procedures

**Adding a new publisher — the Edge-side steps.** Four things, in this order:

1. **Exchange side first.** The publisher's tenant must be set up with
   `signing_scheme = 'ED25519'`, or the delivery address will not carry the
   signature this Worker checks. See [`../exchange/RUNBOOK.md`](../exchange/RUNBOOK.md).
2. **Routes** covering all article paths **and** `/.well-known/*`
   ([`DEPLOYMENT.md`](DEPLOYMENT.md) §6.1), on proxied DNS records (§6.2).
3. **The two discovery documents.** `/.well-known/ramp.json` is always served by
   the Worker; `/.well-known/http-message-signatures-directory` is served only
   when `WBA_KEYS_JSON` is set and returns `404` otherwise, which is legitimate.
   **All discovery documents are generated at request time from the environment
   variables — there are no static files to upload or keep in sync.**
4. **Zone protections that must not conflict with the Worker**
   ([`DEPLOYMENT.md`](DEPLOYMENT.md) §7).

Then run the verification in [`DEPLOYMENT.md`](DEPLOYMENT.md) §8.

**When the Exchange rotates its keys — the Edge-side steps.** Normally **nothing to
do, and no redeploy**: the Worker fetches the Exchange's public keys from its
directory and re-fetches when it meets a key id it does not know, so a rotation
fixes itself.

A redeploy is needed in exactly one case: when `RAMP_VERIFY_KEYS` is set, pinning
the keys. Then add the new key to that variable (keeping the old one until the
Exchange stops using it) and deploy as in §4.1.

Verify either way with a fresh signed address from the Exchange:

```bash
curl -s -o /dev/null -w '%{http_code}\n' "https://<host>/some-article-path?exp=…&sig=…&kid=…"
# Expect: 200

curl -s "$EXCHANGE_WBA_URL"
# Expect: a "keys" array containing the new key.
```

If signatures keep failing after the directory shows the new key, the Worker is
still inside the one-hour cache lifetime — [`CONFIGURATION.md`](CONFIGURATION.md)
§4. Wait for the cache to expire, or publish a new version to start fresh
isolates.

### 4.3 Upgrade and rollback

**Roll back to a previous version.** Cloudflare keeps the Worker's deployment
history; rolling back to a previous version is the fastest option and needs no
build:

```bash
npx wrangler deployments list --env production
# Expect: a list of versions, newest first, with their version ids.

npx wrangler rollback --env production
# Expect: a prompt naming the version being restored, then "Successfully rolled back".
```

The alternative is to check out the previous commit and deploy its bundle again.
Prefer the rollback: it restores exactly the version that was running, including
its variables, and takes seconds.

**Keep `compatibility_date` aligned with the code.** That date pins which version
of Cloudflare's runtime the Worker gets. The value in `wrangler.toml` is the one
the code is developed and tested against; moving it forward on its own — without
the code that was tested against the newer runtime — changes runtime behaviour
under an unchanged bundle. Change it as part of a code change, never alone.

**Emergency shutdown options.** Two options, with very different consequences:

| Action | Effect | Consequence |
|---|---|---|
| **Remove the route** | Traffic bypasses the Worker entirely and goes straight to the origin. | The site works normally for everyone — including AI bots, who now read for free. No gate, no negotiation, no revenue. |
| **Empty the deny list** (`BOT_UA_DENY_JSON = "[]"`) | The Worker still runs; the bot gate matches nothing. | Bots pass free, but signed addresses are still verified and the discovery documents still serve. Reversible with one deploy. |

Removing the route is the stronger action and the right one if the Worker itself
is causing an outage. Emptying the deny list is right when the gate is
misclassifying legitimate traffic and you need the rest of the Worker intact.

---

## 5. Backup and recovery

**Not applicable — and that is on purpose, not something missing.** Do not set up
storage for this component.

The Worker is stateless: it stores nothing of its own. It has **no KV, no D1, no
R2, no Durable Objects and no Queues, and it needs zero bindings**. Every request
is decided on its own from the request itself, the configuration, and the
Exchange's public keys — which are fetched, not stored, and expire after an hour.

There is therefore no state to restore. The only recovery action for the Worker
itself is deploying a bundle again — either the rollback in §4.3 or a fresh
`wrangler deploy`. Everything durable lives elsewhere: the articles at the origin,
the catalog and the transaction records at the Exchange, each with its own backup
routine.

---

## 6. Limitations

- **A delivery address can be used more than once** while it is valid. Single-use
  enforcement is **not implemented yet**; the address's expiry is what bounds it.
  With `RAMP_ENFORCE_BINDING` on — the default — reuse is still limited to whoever
  holds the key the address names, so a leaked address alone is not enough. With it
  off, the address is a bearer credential and expiry is the only bound.
- **The Worker records nothing about deliveries.** Per-delivery records at the
  edge are **not implemented yet** — the Exchange's transaction log is the record
  of what was sold.
- **Cloudflare is the supported platform for this deployment.** Adapters for
  Fastly Compute and AWS Lambda@Edge exist in the source and are tested, but are
  not part of this deployment path.
- **The user-agent lists are an approximate filter, not a security barrier.**
  They keep honest, self-identifying bots out. A scraper that pretends to be a
  browser passes like any visitor; only the signed addresses enforce paid access.
- **Configuration is read once per isolate.** A variable change reaches traffic
  through a new deployment version, not through a live reload.
- **The key-directory cache lifetime is fixed at one hour** and no setting changes
  it. That is the longest a key problem can last after the cause is fixed.

> **Handle a delivery address like a password in a URL**: do not log it, do not
> paste it into a ticket, do not forward it. The address names the agent it was
> issued to (`agent_id`), and with `RAMP_ENFORCE_BINDING` on — the default — the
> Worker requires the caller to prove it holds that agent's key, so a leaked
> address alone is not enough. With the check off (`RAMP_ENFORCE_BINDING =
> "false"`), and on publishers that use CloudFront alone, the address is a
> *bearer credential*: anyone holding a valid, unexpired address can read the
> article with it, and only its short expiry and HTTPS protect it.

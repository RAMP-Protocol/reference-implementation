# RAMP Edge Worker — Deployment Instructions

This document tells you, the DevOps engineer deploying the Worker, everything you
need to put it on a publisher's Cloudflare zone. You do not need to read the
source code. Words that may be new are explained the first time they appear.
Follow the steps in order.

Every setting mentioned here is described in full in
[`CONFIGURATION.md`](CONFIGURATION.md). Once the Worker is running, day-to-day
operation is in [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. What this Worker is, and where it sits

This Worker is a small program that runs on Cloudflare's network, in front of a
publisher's article pages. (A "Worker" is code Cloudflare runs at its edge, close
to the visitor, before the request reaches the real website.) It looks at every
request for an article and decides what to do:

- A normal human with a browser passes straight through to the real website.
- A search engine crawler (for example Googlebot) passes through for free.
- An AI bot with no payment gets a `403` response (HTTP "forbidden") plus
  instructions on how to buy access.
- A paid AI agent sends a "signed URL" (a web address with a cryptographic
  signature attached). The Worker checks the signature and, if it is valid,
  serves the article.

The important idea: the article web address is the **same for everyone**. There
is no separate paid link. This one Worker is the only gate that decides each
request.

```
visitor / crawler / AI bot / paying agent ──► Cloudflare zone ──► Worker ──► Origin
```

The publisher owns the zone, the Worker and the origin. The Exchange — a separate
service, run by the Exchange operator — owns pricing, the signing keys and
settlement. The Worker never holds a private key and never talks to the Exchange
except to fetch its **public** keys.

---

## 2. What you need before you start

| What | Where it goes | How to check you have it |
|---|---|---|
| A Cloudflare account | — | `wrangler whoami` names your account |
| The publisher's zone, active in that account | Worker routes (§6) | The zone appears as **Active** on the account's Websites page |
| An API token with the scopes below | `CLOUDFLARE_API_TOKEN` in your shell | `wrangler whoami` succeeds with the token exported |
| Node.js 20 or newer, and npm | — | `node --version` |
| The address of the Exchange, and its key directory | `EXCHANGE_URL`, `EXCHANGE_WBA_URL` | `curl -s https://exchange.example.com/.well-known/http-message-signatures-directory` returns JSON with a `keys` array |
| The publisher's payee id | `EXCHANGES_JSON` → `ext.resource_owner_id` | Ask the Exchange operator — [`CONFIGURATION.md`](CONFIGURATION.md) §3.5 |
| The origin arrangement | `SAME_ZONE_ORIGIN` or `ORIGIN_URL` | [`CONFIGURATION.md`](CONFIGURATION.md) §3.1 |

**The API token needs exactly three permissions:**

| Permission | Level | What it is for |
|---|---|---|
| Workers Scripts:Edit | Account | Uploading the Worker script |
| Workers Routes:Edit | Zone | Attaching the Worker to the article addresses |
| DNS:Edit | Zone | Confirming and fixing the proxied DNS records (§6) |

Check the token before you go further:

```bash
export CLOUDFLARE_API_TOKEN=<the token>
npx wrangler whoami
# Expect: "You are logged in with an API Token", your account name and ID,
#         and a table of token permissions.
```

**There are no secrets to set up.** Every value the Worker reads is public
configuration, so no secret store and no `wrangler secret` are involved — see
[`CONFIGURATION.md`](CONFIGURATION.md) §1.

---

## 3. Build the bundle

"Bundling" means packing all the source files into one file the runtime can load.
`wrangler deploy` (§5) does this for you, so this step is only needed if you want
to inspect the built file first, or if your pipeline uploads the script directly
rather than calling `wrangler`.

```bash
cd src/edge
npm ci
# Expect: "added N packages" and no error.

npm run build:worker
# Expect: an esbuild summary ending with
#   dist/worker.mjs   <size>
#   built dist/worker.mjs from src/entries/cloudflare.ts (workerd)
```

The single output file is `dist/worker.mjs`. The entry point it is built from is
`src/entries/cloudflare.ts`.

---

## 4. Configure

Every variable, its default, and what happens when it is missing is in
[`CONFIGURATION.md`](CONFIGURATION.md). It is not repeated here.

Fill in the environment block in `wrangler.toml` — `[env.staging]` for staging,
and a matching `[env.production]` block for production. The two items that most
often go wrong, both covered in that document:

1. `EXCHANGES_JSON` must carry `ext.resource_owner_id`, or every catalog push for
   this publisher is rejected (§3.5 there).
2. Exactly one origin mode must be set, or the Worker fails with an error on every request
   (§3.1 there).

Keep `wrangler.toml` as the single authoritative configuration. Variables edited
in the Cloudflare dashboard are overwritten by the next `wrangler deploy`.

---

## 5. Deploy

```bash
cd src/edge
npx wrangler deploy --env staging
# Expect, in order:
#   Total Upload: <size> KiB / gzip: <size> KiB
#   Uploaded ramp-edge-staging (N sec)
#   Deployed ramp-edge-staging triggers (N sec)
#     staging.publisher.example/*
#   Current Version ID: <uuid>
```

The listed triggers are the routes from the environment block. If the list is
empty, or a route you expected is missing, stop and fix the block before going
on — the Worker is uploaded but nothing is sending traffic to it.

Replace `staging` with `production` for the production environment. Deploy each
environment separately; they are independent Workers with independent variables.

---

## 6. Zone-side settings the deploy command does not cover

`wrangler deploy` uploads the script, its variables and its routes. Four things
live on the zone and must be right independently.

### 6.1 Routes must cover every path the Worker owns

A "route" tells Cloudflare which addresses this Worker handles.

- The routes must cover **all** article paths on the publisher's site.
- The routes must **also** cover `/.well-known/*` — the discovery documents bots
  read to learn how to buy access. A route that misses them breaks bot
  negotiation silently: the bot gets a `403` telling it where to go, follows the
  pointer, and finds nothing there.

A single wildcard such as `staging.publisher.example/*` satisfies both. The attached
routes are printed by the deploy command (§5); confirm the discovery path is
actually covered by asking for it:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://staging.publisher.example/.well-known/ramp.json
# Expect: 200. A 404 means the route does not reach the Worker on that path —
#         the origin answered instead.
```

For what those documents should contain once the route reaches them, see the
filled-in copies in
[`../../deploy/publisher-wellknown/`](../../deploy/publisher-wellknown/).

### 6.2 DNS records must be proxied

For every hostname the Worker serves, the zone's DNS record must be **proxied** —
the orange cloud icon in the dashboard, `proxied = true` in an API call. The
Worker runs on proxied traffic only. A record set to "DNS only" (grey cloud) means
the Worker never runs and the gate is bypassed entirely, with no error anywhere.

```bash
curl -sI https://staging.publisher.example/ | grep -i '^server:'
# Expect: server: cloudflare
# Anything else means the record is not proxied.
```

### 6.3 `workers_dev` must be off

By default Cloudflare gives every Worker a free hostname like
`ramp-edge.<account>.workers.dev`. If it is left on, anyone can reach the Worker
through that hostname, bypassing the zone — which also breaks same-zone origin forwarding,
because there is no zone to forward within. `workers_dev = false` is already set
in the checked-in environment block; confirm it is still set after any edits.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://ramp-edge-staging.<account>.workers.dev/
# Expect: curl fails to resolve the host — the hostname is not published.
#         Any HTTP response at all means workers_dev is still on.
```

### 6.4 Observability must be on

"Observability" here means Cloudflare keeps the structured records the Worker
writes — Workers Logs. `head_sampling_rate = 1` means keep 100% of them (`0.1`
would keep one in ten). [`RUNBOOK.md`](RUNBOOK.md) depends on reading these
records; without them you cannot see what the Worker is doing.

The `[observability]` block at the top of `wrangler.toml` applies this on every
`wrangler deploy`. If you deploy by another route, enable it on the Worker in the
Cloudflare dashboard — see §9.

---

## 7. Zone security settings must not conflict with the Worker

Cloudflare's own security features (WAF rules, Bot Fight Mode, Super Bot Fight
Mode, and the "Block AI bots" / AI Crawl Control toggle) run **before** the
Worker. If any of them blocks or challenges a caller, that caller never reaches
the Worker at all. For this product that is a problem, because the Worker must be
the one making the decision:

- **Do not block AI crawlers at the zone level.** The whole point is that an AI
  bot reaches the Worker and gets the `403` answer with purchase instructions. If
  the zone's "Block AI bots" toggle (or Bot Fight Mode) blocks GPTBot first, the
  bot never learns how to pay.
- **Do not challenge signed-URL traffic.** Paying agents fetch articles with plain
  HTTP clients from data-centre addresses — exactly the kind of traffic that
  bot-protection products often challenge. A browser challenge page breaks these clients
  completely. If Bot Fight Mode or a WAF rule covers the article paths, add a skip
  or exception for them, or turn the feature off for this zone.
- **Check that search crawlers are not caught by WAF managed rules.** After
  go-live, look at Security Events for blocked Googlebot or Bingbot traffic and
  add an exception if needed — otherwise the publisher loses indexing even though
  the Worker would have allowed it.

Caching needs no special setup: routed requests always run the Worker first (the
zone cache cannot answer an article request without it), and the Worker's own
fetch to the origin simply follows whatever cache rules the zone already has.

---

## 8. Verify the deployment

Six checks. Replace `<host>` with the real article hostname and
`/some-article-path` with a real article.

**Check A — humans pass through.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  https://<host>/some-article-path
# Expect: 200
```

**Check B — the bot gate works.**

```bash
curl -s -D - -o /dev/null -A "GPTBot/1.0" https://<host>/some-article-path
# Expect: HTTP/2 403
#         x-content-rules: https://<host>/.well-known/ramp.json
#         x-ramp-exchange: https://exchange.example
```

**Check C — discovery works.**

```bash
curl -s https://<host>/.well-known/ramp.json
```

What a correct answer contains, and what a missing or wrong
`ext.resource_owner_id` costs, is in
[`../../deploy/publisher-wellknown/`](../../deploy/publisher-wellknown/) beside a
reference copy of the document. See also [`CONFIGURATION.md`](CONFIGURATION.md)
§3.5.

**Check D — the key directory answers correctly.**

```bash
curl -s -D - https://<host>/.well-known/http-message-signatures-directory
```

Both `200` and `404` are correct answers here, depending on whether this publisher
issues its own signing keys, and neither the status nor the content type proves
the Worker rather than the origin produced the response. Which answer to expect,
and what to compare inside the body, is in the same folder. If the body does not
match what you configured, re-check the routes in §6.1.

**Check E — signed URLs work.** Take a signed address produced by the Exchange
and request it. This needs the Exchange side done first: the publisher's tenant
must be set up with `signing_scheme = 'ED25519'`.

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  "https://<host>/some-article-path?exp=…&sig=…&kid=…"
# Expect: 200
```

A `403` here with a valid, unexpired address usually means the Exchange's key
directory and the Worker disagree — [`RUNBOOK.md`](RUNBOOK.md) §3.1.

**Check F — observability is retaining records.** Open Workers Logs for this
Worker in the Cloudflare dashboard and re-run Check B. Confirm a record named
`edge.deny.bot` appears. If the log stays empty, §6.4 is not in effect and the
runbook's diagnostics will not work.

---

## 9. If a platform team applies this with Terraform

A ready-made module is available at
[`../../deploy/terraform/modules/cloudflare-edge/`](../../deploy/terraform/modules/cloudflare-edge/),
wrapped by the stack in
[`../../deploy/terraform/stacks/edge/`](../../deploy/terraform/stacks/edge/); the
step-by-step version of this page for that route is
[`../../deploy/terraform/docs/deploy-edge-standalone.md`](../../deploy/terraform/docs/deploy-edge-standalone.md).
`wrangler deploy` remains supported and is what §5 describes. A platform team
building its own configuration instead creates the same resources:

| Resource | Setting |
|---|---|
| Worker script | The pre-built `dist/worker.mjs` from §3 |
| Worker vars | The variables from [`CONFIGURATION.md`](CONFIGURATION.md) §2, as plain vars — there are no secrets |
| Worker routes | Article paths **and** `/.well-known/*` (§6.1) |
| DNS records | `proxied = true` for every served hostname (§6.2) |
| `workers_dev` | `false` (§6.3) |
| Compatibility | `compatibility_date = "2026-07-01"`, `compatibility_flags = ["nodejs_compat"]` |
| Bindings | none |

**Observability is a manual step under Terraform.** The Cloudflare Terraform
provider does not support the Workers Logs setting, so do not expect an
`observability` block in the Worker resource to take effect. Enable it on the
Worker in the Cloudflare dashboard with `head_sampling_rate = 1`, and verify with
Check F in §8 after every apply.

---

## 10. Where to go next

This document ends once the Worker is deployed and verified. Everything you do to
it afterwards lives in [`RUNBOOK.md`](RUNBOOK.md):

| Task | Where |
|---|---|
| What to alert on, and what to ignore | `RUNBOOK.md` §2.3 |
| A sudden wave of `403` responses — how to tell normal traffic from a real problem | `RUNBOOK.md` §3.1 |
| Reading the decision for one request | `RUNBOOK.md` §3.2 |
| Deploying a code change, or only changing variables | `RUNBOOK.md` §4.1 |
| Updating the bot pattern lists | `RUNBOOK.md` §4.1 |
| Onboarding another publisher | `RUNBOOK.md` §4.2 |
| What to do when the Exchange rotates its keys | `RUNBOOK.md` §4.2 |
| Rolling back, and the emergency shutdown options | `RUNBOOK.md` §4.3 |
| Why there is nothing to back up | `RUNBOOK.md` §5 |
| Known limitations | `RUNBOOK.md` §6 |

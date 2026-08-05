# RAMP Edge Worker

A Hono app that runs at the edge (Cloudflare Worker, Fastly Compute, or AWS
Lambda@Edge) in front of a publisher's website. It is the single point where
access to licensed content is decided.

## The shared-URL model

The article URL is the same for everyone — real users and AI agents. There is
no separate "licensed" path or hostname. On every request the Worker decides:

| Request looks like | What happens |
|---|---|
| Has the signature parameter `sig` | Verify the Ed25519 signature and expiry (a valid URL also carries `exp`, and `kid` selects the key; a URL with `exp` or `kid` but no `sig` is treated as unsigned). Valid → serve from origin. Invalid or expired → 403, content not served. |
| Signature params include `agent_id` | The Worker also requires proof that the caller holds that agent's key (on by default — see [`CONFIGURATION.md`](CONFIGURATION.md) §3.6). With that check turned off, the address is a *bearer credential*: whoever holds it can read the article until it expires, protected only by its short lifetime and HTTPS. |
| No signature, browser-like client | Pass through to origin untouched. Normal website traffic never sees a 403. |
| No signature, AI-bot User-Agent | 403 with an `X-Content-Rules` header and a JSON body pointing at `/.well-known/ramp.json`, where the bot learns how to buy access. |

The discovery files `/.well-known/ramp.json` and
`/.well-known/http-message-signatures-directory` are always served without any
signature.

The end-to-end proof of all four outcomes on one article path runs on the real
Cloudflare runtime: `npm run test:e2e:article`.

## How the Worker tells bots apart

On an unsigned GET/HEAD request the Worker sorts the caller into one of three
groups: a **human** (pass through), a **search crawler** (pass through — the
publisher wants indexing and the visits it brings), or an **AI bot** (403 with
the pointer to buy access). Other methods (form posts, webhooks) skip this
check entirely.

The decision uses these inputs, in priority order — the first match wins:

1. **Cloudflare's verified-bot data** (`request.cf.verifiedBotCategory`).
   The platform verifies crawlers by network and behavior, so this takes
   priority over anything the caller writes into its User-Agent. A verified
   `Search Engine Crawler` is allowed through without payment; a verified AI
   crawler (`AI Assistant`, `AI Crawler`, `AI Search`) receives the 403
   payment response even if its User-Agent is not on our list yet. If both
   categories apply, the bot is treated as a search crawler — blocking a
   search engine by mistake harms the publisher more than letting an AI
   crawler read for free.
2. **The search-crawler allow list** — User-Agent patterns for Googlebot,
   Bingbot, DuckDuckBot, Applebot (but not Applebot-Extended, Apple's AI
   crawler), YandexBot. Free pass-through.
3. **The AI-bot deny list** — User-Agent patterns for GPTBot, ClaudeBot,
   Google-Extended and other AI crawlers, plus generic bot/crawler/spider
   markers. These get the 403 with the link that explains how to buy access.
4. **No User-Agent at all** counts as a bot (normal browsers always send
   one). Anything else is a human and passes.

Both pattern lists can be replaced without a code deploy: set
`BOT_UA_ALLOW_JSON` / `BOT_UA_DENY_JSON` (JSON arrays of patterns, at most 64
entries of 256 characters each — anything larger is rejected outright rather than
trimmed, and the rejection lands on every request rather than on the deploy).

One known limitation: steps 2–4 read the User-Agent, which callers choose
freely. They keep honest, self-identifying bots out — they are not a security
barrier. A scraper that pretends to be a browser passes like a normal visitor;
paid access is enforced only by the signed URLs, and stealth-bot detection is
the CDN's bot-management product, not this Worker.

## Supported platforms

The access logic is written once, as a runtime-agnostic Hono app (`src/app.ts`
and the modules it imports). It does not depend on any specific CDN. Each CDN
is reached through a small adapter under `src/entries/` — a small file that
starts the shared app and passes it that platform's configuration. There are
three today:

| Platform | How it runs the app | How configuration reaches it |
|---|---|---|
| **Cloudflare Workers** (the default deployment target, deployed with Wrangler) | `cloudflare.ts` exports a `fetch` handler the runtime calls per request | The runtime hands over the whole settings object; the adapter passes it straight through. `SAME_ZONE_ORIGIN` works only here. |
| **Fastly Compute** | `fastly.ts` registers a `fetch` listener | Fastly has no settings object you can list, so `fastly.ts` asks for each setting by name, one at a time. A missing name would silently lose that setting on Fastly only, so a parity test checks the list stays complete. |
| **AWS Lambda@Edge** | `aws-lambda.ts` wraps the app with `hono/lambda-edge` and exports a Lambda `handler` | The runtime provides settings as process environment; the adapter passes them straight through. |

How each is tested:

- **Cloudflare** runs on the real Workers runtime (`workerd`) through the
  Workers vitest projects — this is where the four-outcome article suite runs.
- **Fastly** and **Lambda@Edge** are driven by plain Node test harnesses in the
  `node` project (no CDN command-line tools needed).
- On top of that, both Fastly and Lambda@Edge get a full run inside the
  Docker-based E2E stack (`tests/e2e/fastly-edge/` and `tests/e2e/aws-edge/`),
  which drives the whole Agent → Broker → Exchange → Edge → Origin flow.

Adding a new CDN means writing one more adapter in `src/entries/`. The shared
app does not change.

## Key material — the Worker holds no secrets

- The **private** Ed25519 signing key lives only in the Exchange's key store
  (Vault-backed). It is never given to Cloudflare or to the publisher.
- The Worker verifies signed URLs with the Exchange's **public** key. It gets
  that key in one of two ways:
  1. **Default**: fetch at runtime from `EXCHANGE_WBA_URL` (the Exchange's
     public-key directory). Keys are matched by the `kid` in the URL (an
     RFC 7638 thumbprint) and cached in memory for one hour. A `kid` that is
     not in the cached set is refused until the cache expires, so after a key
     rotation on the Exchange, URLs signed with the new key can get 403s for
     up to one hour (see `RUNBOOK.md` §4.2). No Worker redeploy is needed —
     the next fetch picks the new key up.
  2. **Optional pinning**: set `RAMP_VERIFY_KEYS` to a JSON array of public
     JWKs. The Worker then verifies without any network fetch. When a `kid`
     is not in the pinned set, the Worker makes one directory fetch to look
     it up — so in this mode a rotation heals itself immediately.
- Every configuration value is public, so plain Wrangler `[vars]` are enough —
  nothing needs `wrangler secret`.

## Origin contract — what we need from the publisher

The Worker must know how to reach the website's backend ("origin"). Two modes:

1. **Same-zone mode** (`SAME_ZONE_ORIGIN=true`) — no origin address needed.
   The Worker re-fetches the incoming URL (signature parameters removed) and
   Cloudflare routes that subrequest to the zone's configured origin with the
   original `Host` header. This is the right mode when the backend is a shared
   load balancer that routes by `Host` (for example an internal LB serving
   several sites). Same-zone subrequests do not re-enter the Worker, so there
   is no loop.
2. **Explicit origin** (`ORIGIN_URL=https://...`) — the Worker rewrites the
   request to that backend, keeping path and query. The backend will see its
   own hostname in `Host`, so this mode only fits an origin dedicated to the
   site. The address must not resolve back to the Worker's route.

On Cloudflare and Fastly the Worker fails with a clear error on every request
when neither mode is configured, rather than serving empty pages. The check runs
per request, not at deploy time, so the deployment itself succeeds. Fastly
supports only the explicit `ORIGIN_URL` mode (same-zone forwarding is a
Cloudflare routing behavior).

**AWS Lambda@Edge is deliberately exempt from this check.** On AWS the roles
are reversed: CloudFront verifies its RSA signed URLs natively (trusted key
group) and CloudFront fetches the origin itself; the Lambda function sits in
front only for the bot gate (the check that blocks unpaid AI bots) and the
discovery routes. Running it without `ORIGIN_URL` is the intended production
shape there, so the guard must not apply — this difference is intentional;
do not add the check to the AWS adapter.
(Setting `ORIGIN_URL` on Lambda still works if a deployment wants the Worker
to proxy.)

Rules the origin should follow:

- Redirects are passed back to the visitor unchanged, so `Location` values
  should be relative (or use the public hostname), never an internal address.
- The query parameter names `exp`, `sig`, `kid`, and `agent_id` are reserved
  by the signed-URL scheme. On signed requests they are removed before
  forwarding; the site should not use these names for its own purposes.
- POST/PUT and other non-read methods on *unsigned* requests are forwarded
  as-is (body included) and are never bot-gated; GET/HEAD without a signature
  go through the bot check.
- A *signed* URL authorizes reading only. The signature covers the URL, not
  the method or body, so a signed request with a write method is always
  refused (405).

## Deploying for a publisher zone (Cloudflare)

For the full list of what a deployment must create (routes, variables,
observability, verification checks) written for DevOps/Terraform work, see
[DEPLOYMENT.md](DEPLOYMENT.md). In summary:

1. **Exchange side**: provision the publisher's tenant with
   `signing_scheme = 'ED25519'`. The Exchange then signs the catalog URI
   itself — the delivery URL is the article URL plus the signature query
   parameters; no URL mapping is introduced.
2. **Worker side**: fill in the `[env.staging]` block in `wrangler.toml`
   (routes for the article paths, plus the variables listed there; the
   comments mark what still needs publisher-specific input, e.g. `ORIGIN_URL`), then:

   ```bash
   wrangler deploy --env staging
   ```

3. Verify against the staging zone: an unsigned browser request returns the
   article; an unsigned bot User-Agent gets the 403 with the link that
   explains how to buy access; a signed URL from the Exchange returns the
   article.
4. Repeat with a production environment block after staging works correctly.

## What to alert on

The Worker writes one structured record per decision (visible in Workers
Logs). Denials are logged as warnings and are normal traffic; the error level
means something is broken:

- `edge.origin.fetch_failed` (error) — the origin is down or its address is
  wrong; visitors are getting 502s.
- `edge.keys.load_failed` (error) — the Exchange's key directory is
  unreachable or returned data the Worker could not read; paying agents
  start getting 403s unless keys are pinned.
- `edge.verify.unavailable` (error) — a signed-URL check could not run
  because key loading failed; the caller got a retryable 503. Usually
  appears together with `edge.keys.load_failed`.
- A sudden increase in `edge.deny.signature` (warn) — agents present bad or expired
  URLs; usually an Exchange key-rotation or clock problem.
- `edge.deny.bot` / `edge.deny.binding` / `edge.deny.method` (warn) —
  expected: unpaid bots, leaked-URL attempts, and signed read URLs replayed
  with a write method.

## Scripts (`scripts/`)

Three small scripts live here. Two of them let the Worker run **outside
Cloudflare** — inside the Docker-based E2E/demo stack — on a real Workers
runtime:

- `build-worker.mjs` — bundles the Cloudflare entry (`src/entries/
  cloudflare.ts` with all its imports) into one file, `dist/worker.mjs`,
  using esbuild. On a real deploy `wrangler deploy` does this bundling
  itself; in a container nothing else would, so this script is the
  substitute. Run with `npm run build:worker`; used by the build stage of
  `Dockerfile.miniflare`.
- `serve-miniflare.mjs` — serves that pre-built bundle with Miniflare (the
  local Workers runtime) as a plain HTTP server, turning the container's
  environment variables into the Worker settings `parseEnv` expects. The
  port is 8787 by default; the E2E stack sets `PORT=80`, so the Python test
  harness and the demo reach the service at `edge:80`. (The name `edge:8787`
  still appears inside signed URLs as the public hostname the Exchange signs
  for; the harness rewrites it to the real service address before fetching.)

The chain: `Dockerfile.miniflare` → build script makes the bundle → serve
script hosts it → the E2E harness drives the full Agent → Broker → Exchange
→ Edge → Origin flow against a real Workers runtime.

These two scripts are not part of the production path (`wrangler deploy`
bundles on its own), and the vitest suites do not use them either
(`@cloudflare/vitest-pool-workers` builds and hosts the Worker itself).

The third script **is** part of a deployment path:

- `build-lambda-edge.mjs` — builds the AWS Lambda@Edge bundle. Lambda@Edge
  has no environment variables, so this script bakes a per-deployment config
  file into the bundle and smoke-invokes the result so a broken config fails
  the build, not the deploy. The AWS deployment tooling
  (`deploy/terraform/scripts/build-lambda-edge.sh`) and the E2E stack's
  `lambda-edge` service both call it.

## Development

```bash
npm test                  # every project in vitest.config.ts (workers, article-path, wellknown-keyless, node — the node project includes the AWS Lambda and Fastly harnesses)
npm run test:e2e:cf       # Cloudflare-runtime E2E
npm run test:e2e:article  # shared-URL four-outcome E2E (origin pass-through)
npm run lint              # biome (warnings are errors) + type-aware floating-promise check
npm run typecheck         # tsc --strict
```

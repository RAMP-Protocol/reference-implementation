# Handoff — Edge Free-Index Fast Path (Web Bot Auth) demo

**Created:** 2026-06-15. **For:** a fresh session picking this up *inside this repo* (`RAMP-Protocol/reference-implementation`). **Status:** ✅ implemented on `feature/free-index-path` (local core proven on miniflare; AWS deploy prepared, awaiting maintainer apply).

## Implemented (what landed)

| Spec item | Lands as |
|---|---|
| WBA verifier (D2/D3) | `src/edge/src/wba.ts` + `tests/wba.test.ts` (signer round-trip) |
| Free-rule projection (D5/D12, static) | `src/edge/src/freerule.ts` |
| Deployed handler single-source | `src/edge/src/cloudfront-edge.ts` + `tests/cloudfront-edge.test.ts` |
| Hono multi-runtime wiring | `src/edge/src/app.ts` / `types.ts` / `config.ts` |
| Local proof (one-request serve; unsigned-bot 403) | `tests/e2e.cloudflare.test.ts` |
| Deploy bundle (config baked at build) | `src/edge/scripts/build-lambda-edge.mjs` + `scripts/fixtures/edge-config.demo.mjs` |
| Demo crawler/signer (D2/D3, real RFC 9421) | `scripts/wba-crawl.py` (cross-verified against `wba.ts`) |
| Ledger free mode + compare (D8) | `scripts/ledger.py --free/--compare` + `scripts/ledger_free.py` |
| Deploy wiring (build prep) | `pi-terraform/.../aws-ramp-demo-lambda/edge-config.mjs` + regenerated `index.mjs` (uncommitted, maintainer review) |
| Pre-stage `.md` + publish bot directory + `terraform apply` | **maintainer** — see `RUNBOOK-aws-demo.md` §"Free-index fast path" |

The original spec follows, unchanged, for context.

---

---

## 0. TL;DR — what to build

Add a **Web-Bot-Auth–verified free-index fast path** to the edge worker so that a cryptographically-identified crawler indexing *free* content gets the content in **one request** — no Exchange round-trip — while the access is still **cryptographically recorded**. Then extend `scripts/ledger.py` so the existing **6-row paid chain visibly collapses to a 2-row free chain**. That side-by-side trace *is* the demo.

The thing people think is missing — Web Bot Auth — is mostly *present in primitive form already*. The edge has Ed25519 verification (`crypto.subtle.verify('Ed25519', …)`); it just applies it to *signed URLs*, not *signed requests*. We add the request-signature verifier (real, standards-compliant) and **bring our own demo crawler** as the signer. Mechanism real; only the crawler *identity* is synthetic.

---

## 1. Source of truth (read first)

The design of record is **ADR-015** in the sibling repo:

```
/Users/konst/projects/agentic-content-access/docs/architecture/adr-015-edge-free-index-fast-path.md
```

Read it if reachable. This note embeds enough to stand alone if it is not. ADR-015 decisions, one line each:

- **D1** — fast path fires on a *term class*, not an actor: `ENUMERATED` + `Pricing{FREE, metering:NONE}` + a single `FUNCTION` restriction (`permitted ⊆ {crawl, ai-index, search}`) + **no** quota/obligation/geo/user-type/critical + empty scopes. Any deviation → full Exchange cycle.
- **D2** — identity = Web Bot Auth (RFC 9421 Ed25519 request signature; bot keys at a `.well-known` directory). UA strings are advisory only; never authorize a free serve on a UA match.
- **D3** — acceptance = a **signed purpose header** (provisional `RAMP-Purpose`, AIPREF vocab: `search`/`ai-index`/`crawl`) that **MUST be covered by the signature** (present in `Signature-Input`). Uncovered/absent → not fast-path-eligible.
- **D4** — response carries `Content-Usage` (AIPREF) + a license pointer (data-labels TDL id, immutable) as *notice*; the binding act is D3's signed request, not the response.
- **D5** — the edge is **pure read** at request time. It reads config; it never writes/refreshes/invalidates it.
- **D6** — decision ladder: valid WBA sig covering purpose? → fast-path-eligible (allow/deny)? → free term matches path? → serve markdown from cache + record. Any "no" → `403 → Exchange`. Allow/deny gates the *fast path only*, never access.
- **D7** — ingestion **generates and hosts** the markdown rendition (typical publisher is WordPress, has none).
- **D8** — the free-tier access record extends the ADR-012 delivery log (unmetered variant), batch-synced to reconciliation. The signed record *is* the evidence.
- **D9/D12** — one declared catalog → two projections (Exchange catalog + edge config). A background job **collapses** high-fidelity terms into a few path-pattern rules + an **exclude-only** exception list; any per-resource deviation becomes an exception → full cycle.
- **D11** — implementation-level; the one standards move is the signed purpose component (WG ask, Jira RAMP-41).

**This demo realizes D2/D3 for real and stubs D7/D9/D12 as static edge config** (see §4 stubs). That is the correct scope for a *concept* demo.

---

## 2. The concept, self-contained

A free-index license term has **nothing for the Exchange to do**: no spend, no quota, no billing id, no signed-URL binding, no reporting obligation. So the round-trip (`DiscoverResources → ExecuteTransaction → signed URL → fetch → ReportUsage`) is pure latency for that class. We collapse it to a single edge-resolved request, gated on WBA identity + a signed purpose, and we log a signed record so the publisher still has a full ledger of who indexed what under which license. Per-URL grounding (`ai-input`, priced, metered) keeps the full cycle.

---

## 3. The WBA gap and how this demo closes it

**What the edge does today** (`src/edge/src/app.ts`, `catchallHandler`):

```
GET *  →  if no ?sig param:
            if looksLikeBot(UA)  → denyBot()  (403 + X-Content-Rules → ramp.json)
            else                 → passToOrigin()
          if ?sig present:
            verifyEd25519SignedUrl()  → pass / 403
```

So: UA bot-deny + **URL**-signature verification. No RFC 9421 **request**-signature verification. That is the only real gap.

**How we close it:**
- **Verifier (build for real).** RFC 9421 request-signature verification reuses what's already here: `crypto.subtle.verify('Ed25519', …)` and `decodeBase64Url` (`src/edge/src/verify.ts`), and the JWK→CryptoKey import in `src/edge/src/keys.ts`. The only new logic is building the RFC 9421 *signature base* from the covered components and resolving the bot's key from its directory.
- **Signer (bring our own).** A small demo crawler script that publishes an Ed25519 JWK directory and signs its GET. The mechanism is identical to what a real WBA crawler (or Cloudflare's verified-bots-with-crypto fleet) would send; only the identity is ours. Say this plainly in the demo.

---

## 4. Build plan (exact files in THIS repo)

### Item A — Edge WBA-verify fast path (the core, real)
- **New:** `src/edge/src/wba.ts` — `verifyWebBotAuthRequest({ method, authority, path, headers, resolveBotKey })`:
  - parse `Signature` / `Signature-Input` (tag `web-bot-auth`); read covered component list.
  - **reject unless** `ramp-purpose` (the purpose header), `@authority`, and `@path` are all in the covered list (this is the keystone — uncovered purpose = no agreement).
  - build the RFC 9421 signature base over the covered components; `crypto.subtle.verify('Ed25519', botKey, sig, base)`.
  - return `{ valid, kid, purpose, reason }`. Reuse `decodeBase64Url` from `verify.ts`, JWK import from `keys.ts`.
- **New:** `src/edge/src/freerule.ts` — `matchFreeRule(path, rules)` → `{ licenseId, contentHash, renditionPath } | undefined`. Pure, table-driven (the collapsed rule, D5/D12).
- **Edit:** `src/edge/src/app.ts` `catchallHandler`, inside `if (!hasSig)` **before** `looksLikeBot`:
  ```
  const fast = await tryFreeIndex(c, deps);   // WBA verify + purpose covered + free-rule match
  if (fast) return fast;                       // 200 (markdown via passToOrigin) + free-index log line + D4 headers
  if (looksLikeBot(userAgent)) return denyBot(c, deps);
  return passToOrigin(c, deps);
  ```
  On success: serve the rendition via `passToOrigin` (rewrite pathname to `renditionPath`), set `Content-Usage` + `X-RAMP-License` headers (D4), and emit the free-index decision log line (Item E schema).
- **Edit:** `src/edge/src/types.ts` `AppDeps` — add `freeRules`, `resolveBotKey` (fetch+cache the bot directory referenced by `Signature-Agent`), `licensePointer`.
- **Tests:** `src/edge/tests/wba.test.ts` (pure, mirror `verify.test.ts`) + extend `src/edge/tests/e2e.cloudflare.test.ts` (miniflare) to prove a signed crawler gets 200 in one request and an unsigned bot still gets 403.

### Item B — Free-rule config = the collapsed rule (D5/D9/D12) — **stub**
For the demo, hardcode one or two free path prefixes + their rendition path + license id in the runtime entry deps (`src/edge/src/entries/*.ts`). Production note in a comment: "the D12 projection derives this from the catalog; here it is a static list." Do **not** build the catalog→projection job in the demo.

### Item C — Markdown rendition (D7) — **stub**
Pre-stage a `.md` artifact in S3 `ramp-demo-content` for the free path. `passToOrigin` already rewrites pathname + forwards to origin, so serving the `.md` is just pointing the free rule at its key. No WordPress pipeline.

### Item D — Demo crawler = the signer (D2/D3, real mechanism)
- **New:** `scripts/wba-crawl.py` — stdlib + `cryptography` (or PyNaCl), mirroring the ethos of `scripts/mint-signed-url.py`:
  - generate/load an Ed25519 keypair; emit a JWK directory JSON (host it where the edge can fetch it — an S3 object under a Lambda-bypassed path, or a separate static host).
  - sign a GET over covered components `("@authority" "@path" "ramp-purpose")` with `tag="web-bot-auth"`; send `RAMP-Purpose: ai-index`, `Signature`, `Signature-Input`, `Signature-Agent`.
  - print the resulting `req_id` / `sig_prefix` so the ledger can join.

### Item E — Ledger free mode (D8, reuses real logs)
- **Edit:** `scripts/ledger.py` — add `--free` / `--req <req_id>` mode:
  - the edge Lambda emits a free-index JSON log line (extend the existing decision-log emit in `src/edge/src/entries/aws-lambda.ts`): `{ req_id, purpose, bot_kid, sig_prefix, decision: "pass:free-index", license_id, content_hash, uri, ua }` — **no** `tx_id`.
  - join by `req_id` (current paid mode joins by `tx_id`); render the **2-row** chain: (1) *bot signed intent*, (2) *edge served + recorded*.
  - cross-assertion: re-fetch the bot's published JWK by `bot_kid`, re-verify that `sig_prefix` came from that key → `✓ bot signed this intent`. (Same "assert the stored bytes match, derive nothing" spirit as the paid ledger.)
  - add a `--compare TX=<paid> REQ=<free>` to print both chains side by side.

---

## 5. The money shot (target output)

```
PAID — grounding (ai-input)                          FREE-INDEX (ai-index)
party     step                                       party   step
exchange  1. offer issued       offer_sig=…          bot     1. signed intent   RAMP-Purpose=ai-index
broker    2a. broker routed     ✓ selected exch      bot        (Signature-Input covers @authority @path ramp-purpose)
exchange  2b. offer accepted    ✓ offer_sig          bot        sig_prefix=AbC…
exchange  3. ledger row         url_sig=…            edge    2. served + recorded  decision=pass:free-index
edge      4. signed-URL hit     ✓ url_sig matches    edge       ✓ re-verify sig_prefix vs bot JWK kid=K
edge      5. origin served      decision=pass:signed edge       served s3://…/article.md  (one request)
exchange  6. usage reported     ✓ state=RECEIVED
6 rows, full RAMP cycle                              2 rows, edge-only, still cryptographically attributable
```

That collapse is the entire pitch.

---

## 6. Real vs staged — say this in the demo

| Real | Staged |
|---|---|
| RFC 9421 / Ed25519 request-signature verification | crawler identity is our demo bot, not GPTBot |
| signed purpose declaration + coverage enforcement | the free rule is static config, not a catalog projection |
| non-repudiable signed access record + ledger re-verify | the markdown is pre-staged, not pipeline-rendered |
| edge serve-vs-redirect decision; `Content-Usage` + license labeling | allow/denylist is trivially "our bot" |

Every staged item is a labeled stub *around* a real cryptographic core.

---

## 7. Deployed-state facts you need (from `docs/HANDOFF-aws-demo.md`, `RUNBOOK-aws-demo.md`)

- Topology: CloudFront → S3 `ramp-demo-content`; **Lambda@Edge is the sole gate**; tenant `signing_scheme=AWS_CLOUDFRONT_RSA`.
- `/.well-known/*` has a dedicated cache behavior with **no Lambda** (so `ramp.json` is always fetchable; bots following `X-Content-Rules` don't 403-loop). Useful for hosting the bot directory under a bypassed path if you choose S3.
- Lambda log group: `/aws/lambda/us-east-1.ramp-demo-edge-bot-redirect` (Lambda@Edge logs land in the POP's region — `ledger.py` already scans a region set).
- Trace endpoint: Exchange `GET /admin/ledger?tx=<id>` (paid mode). Free mode joins Lambda logs by `req_id`.
- Edge runtime entries: `src/edge/src/entries/{aws-lambda,cloudflare,fastly}.ts` wire `AppDeps`; the decision log line is emitted in the **aws-lambda** entry — add the free-index variant there.
- Reuse: `scripts/mint-signed-url.py` (signer ethos), `scripts/ledger.py` (trace), `src/edge/src/verify.ts` (Ed25519 + base64url), `src/edge/src/keys.ts` (JWK import).

---

## 8. Suggested sequence (most of it runs locally — no AWS until step 6)

1. Read ADR-015 (§1).
2. `src/edge/src/wba.ts` + `wba.test.ts` — pure, no infra. Get RFC 9421 base construction + coverage enforcement right here.
3. `freerule.ts` + wire the fast-path branch in `app.ts` + `AppDeps`.
4. `scripts/wba-crawl.py` + extend `e2e.cloudflare.test.ts` (miniflare) to prove **one-request free serve** and **unsigned-bot 403**. `make test-e2e` validates locally.
5. `scripts/ledger.py --free` + the free-index Lambda log line schema (works against local logs / fixtures first).
6. **Deploy (Constantine handles deploy)**: pre-stage the `.md` in S3, set the free rule in the aws-lambda entry deps, ship the Lambda, run `wba-crawl.py` against `demo.ramp-protocol.org`, then `ledger.py --compare`.

Steps 2–5 need no AWS. Build and prove the whole mechanism on miniflare/fastly-serve first; only 6 touches the deployed stack.

---

## 9. Scope guardrails

- **Do not touch the catalog proto / add `LicenseTerm`.** This repo's proto predates ADR-014; the fast path runs entirely from edge config. The term-driven projection (D1/D12) is demonstrated *as config*, not as catalog machinery.
- **Purely additive.** The fast-path branch goes *before* the UA-403 and must not change the existing signed-URL or bot-redirect behavior. Existing e2e tests must stay green.
- **Edge stays pure read (D5).** No KV writes on the request path. The log line is the only side effect.
- **Identity authority is the WBA signature, never the UA.** A UA match must never release bytes.

---

## 10. Open questions (carry from ADR-015 §"Open questions")

1. Purpose header name + exact covered-component set (`RAMP-Purpose` vs an AIPREF-aligned request construct) — the WG ask, Jira RAMP-41.
2. Markdown hosting + access control (public vs short-TTL signed) and how `content_hash` updates propagate.
3. Free-tier record: a new `DELIVERY_OUTCOME_FREE_INDEX_SERVED` in the ADR-012 schema vs a separate log (leaning: same log).
4. Demo-specific: where to host the bot JWK directory; whether to also aim a real Cloudflare-verified WBA client at the endpoint to show third-party interop.

---

## 11. Tracking

- Design tracked under **ADR-015** (sibling repo) and Jira **RAMP-31** (Web Bot Auth / identity epic); the purpose-component standardization is **RAMP-41**. File the implementation tasks under RAMP-31 when you start.
- Conventions in this repo: `make quality` is zero-tolerance; `make test-e2e` is the local proof; never commit secrets/keys; deploys are done by the maintainer, not the agent.

---

## 12. One-paragraph orientation for the next session

You are adding a real RFC 9421 / Ed25519 request-signature verifier to the edge worker (`src/edge`) plus a demo crawler that signs, so that a signed crawler declaring `ai-index` gets free content in a single edge-served request, recorded with its signature; then you extend `scripts/ledger.py` to show that this collapses the existing 6-row paid transaction chain to a 2-row free chain that is still cryptographically verifiable. The full rationale and cross-system design is ADR-015 in `../../agentic-content-access/docs/architecture/`. Build and prove on miniflare locally before deploying. The only thing you are *not* building is real catalog→edge projection and real third-party crawler identity — those are clearly-labeled stubs around a real cryptographic core.

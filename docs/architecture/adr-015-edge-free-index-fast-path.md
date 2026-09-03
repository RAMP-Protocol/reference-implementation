# ADR-015 — Edge Free-Index Fast Path (Web Bot Auth)

**Status:** Accepted (2026-06-15). Demonstrated on the reference implementation, branch `feature/free-index-path` (PR #2): the WBA verifier, the signed-purpose coverage keystone, and the paid-vs-free ledger collapse are realized for real; D4/D7/D8/D9/D10 are simplified, stubbed, or deferred for the demo (see §Realization status). First production targets: identity & interop (Web Bot Auth) plus a new edge/ingestion epic derived from this ADR. Builds on ADR-014 (Universal Licensing Core), ADR-012 (Edge Delivery-Log), ADR-011 (three-way reconciliation), ADR-009 (identity boundary), ADR-002 (two-Biscuit model). · **D8's "no signed-URL HMAC" names a scheme that was never implemented** — see the amendment at the end of `## Decision`.

---

## Context

ADR-014 made the free-index license a first-class, declarable term: a `LicenseTerm` with `Pricing{model: FREE}`, `metering: NONE`, a `Restriction{kind: FUNCTION, permitted: [crawl, ai-index, search]}`, no blocking obligation, and empty `scopes` (public). See ADR-014 §"All-rights-reserved with RSL AI licensing" (term 1) and §"CC0".

For that term class **there is nothing for the Exchange to do.** Walk the round-trip the protocol defines (`DiscoverResources` → `ExecuteTransaction` → signed URL → fetch → `ReportUsage`, discovery-paths Path A/C) and every reason for it evaporates: no spend to authorize, no quota to decrement, no `billing_id` to mint, no per-identity signed URL to bind (`agent_identity_hash`), no reporting obligation to attach. The Exchange exists to price, meter, bill, obligate, and dispute. A free/unmetered/public/no-obligation term triggers none of those.

Yet today a crawler indexing free content still pays the full round-trip. At web-crawl scale that is pure latency and the single largest adoption objection from large crawler fleets ("you put a transaction in front of content I serve free anyway"). The Web Bot Auth port removes the last missing piece: cryptographic crawler **identity** at the edge, using the same Ed25519 / RFC 9421 / well-known-JWKS stack RAMP already mandates (authentication.mdx §"WebBotAuth Compatibility"; [draft-meunier-web-bot-auth-architecture-02](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture-02)).

This ADR decides to **collapse free-index access to a single edge-resolved request** — gated on WBA identity plus a signed purpose declaration — and models how that decision reflects across ingestion, the edge, edge config, reconciliation, identity, onboarding, and the protocol/standards boundary. It is an implementation-and-delivery contract (like ADR-012), not a new wire message.

---

## Decision

### D1 — The fast path is term-driven, not actor-driven

The edge MAY resolve and serve a resource **without an Exchange transaction** iff a `LicenseTerm` for the requested path is the **plain free-index shape** — and nothing more:

- `semantics = ENUMERATED`;
- `Pricing.model = FREE` and `Pricing.metering = NONE`;
- exactly one `Restriction`, of `kind: FUNCTION`, whose `permitted` ⊆ {`crawl`, `ai-index`, `search`} and covers the bot's declared purpose (D3);
- **no** `Quota`, **no** `Obligation` (of any kind), and **no** `GEOGRAPHY` / `USER_TYPE` / `critical` restriction;
- `scopes` empty (public) — satisfiable offline without resolving a Biscuit.

The edge enforces exactly this one rule. It does **not** interpret obligations, scopes, geographies, user-types, or quotas — their mere *presence* is the signal to route full-cycle, not something the edge evaluates. **Any** deviation in **any** dimension makes the term ineligible and the request falls through to the Exchange (D6); the projection that detects deviations and collapses the rest is D12. This is fail-closed toward the Exchange: when a term is anything other than the plain grant, the Exchange — not the edge — owns it.

(This supersedes an earlier, more permissive reading that let `ATTRIBUTION`/`NOTICE` ride the fast path. An attribution obligation is recorded and enforced only through the full cycle's `UsageReport.AttributionDetail` — and arguably belongs to the `ai-input`/display tier anyway, since a pure index has nothing to display.) Crawling is merely the dominant case where terms take the plain shape — the gate is the term, so the rule generalizes and degrades gracefully. Direct corollary of ADR-014's principle that enforcement venue follows term semantics.

### D2 — Identity is Web Bot Auth, verified offline at the edge

The requester is identified by its RFC 9421 HTTP Message Signature under the Web Bot Auth profile: `Signature` + `Signature-Input` (with `tag="web-bot-auth"`), and `Signature-Agent` pointing to the bot's HTTP Message Signatures Directory. The edge verifies against the bot's published Ed25519 JWKS, cached locally (the same caching contract as `ramp.json`). No JWKS fetch on the hot path after warmup.

**User-Agent strings are advisory only.** They may trigger the existing "barking dog" `403` for bots that did not sign (bot-detection.mdx), but a UA match MUST NEVER authorize a free serve — the consequence of a false match is giving content away. Authorization for the fast path requires a valid WBA signature. This is the same two-tier rigor as ADR-012/threat-model: cheap heuristics for redirect, cryptographic identity for anything that releases bytes.

### D3 — A signed purpose declaration is the acceptance primitive

WBA proves identity, not agreement to terms. To make acceptance explicit and non-repudiable **without a round-trip**, the bot sends a request purpose header — `X-Intended-Use` — carrying an **AIPREF-aligned** token (`search`, `train-ai`/`ai-train`, `ai-index`, `crawl`/`scrape`). The header name is settled; the open item is only whether to standardize the component through the WG (Open Question 1).

The edge MUST require that the purpose header is **listed in `Signature-Input`** (i.e. covered by the WBA signature). If it is absent or uncovered, the request has identity but no signed intent → it is not fast-path-eligible (D6). The covered set is `(@authority, @path, X-Intended-Use)`; the signature over it is the binding act — a non-repudiable, edge-verifiable, offline assertion: "I, this bot, am fetching this URL for purpose `ai-index`." The **governing license is named by the publisher** — the matching free rule and the D4 response label (an immutable TDL id) — not co-signed by the bot; the bot's acceptance is of the declared purpose *under the publisher's published terms for that path*. (Whether to also place the license id in the covered set, so the bot co-signs the specific license rather than only the purpose, is Open Question 1.) This is the lightweight equivalent of a Biscuit for the zero-cost case; with no spend cap or quota to carry, the WBA signature plus the covered purpose header is sufficient and no token issuance is required.

Vocabulary reuse is mandatory: the purpose token comes from the AIPREF / RSL function vocabulary already registered in ADR-014 (`ai-train` ↔ `train-ai`, `crawl` ↔ `scrape`). RAMP does not mint a third vocabulary.

### D4 — Publisher labeling rides the response; the binding act is the signed request

On a fast-path serve the edge emits, as **notice/labeling**:

- the AIPREF `Content-Usage` response header (the IETF-standard publisher→bot preference expression; [draft-ietf-aipref-attach](https://datatracker.ietf.org/doc/html/draft-ietf-aipref-attach-04)); and
- a license pointer — `License.id` / `License.uri` of the governing term, preferring a **data-labels TDL** identifier with `immutable: true` (ADR-014 §"License identity"). An immutable, content-addressed license document is what makes "they agreed to *this*" provable later.

The response label alone is browsewrap (content already served) and legally weak; it is deliberately **not** the thing being agreed. The binding act is D3's signed pre-assertion. The response label is defense-in-depth and standards interop. On runtimes that decide at viewer-request (CloudFront Lambda@Edge), attaching the label is naturally an origin-response concern and MAY be deferred there; the multi-runtime Hono path attaches it inline. Either placement is fine — the labeling is not the binding act.

### D5 — The edge is pure read at request time

At request time the edge function **only reads** per-publisher config (the path-pattern ruleset and the allow/denylist, D9/D10) from the CDN-native edge-data store — Cloudflare Workers KV, Fastly Config Store/KV, or CloudFront KeyValueStore (the last because Lambda@Edge cannot make network calls cheaply in viewer-request). It performs the WBA verification (D2), the signature-coverage check (D3), and the term match (D1), then serves or falls through. **It never writes, refreshes, generates, or invalidates config.** All mutation is the background job's responsibility (D9). This keeps the serving function cacheable, offline, and isolated from the control plane's health — the same isolation principle as ADR-012 D6.

### D6 — The decision ladder; allow/deny gates the fast path only

```
WBA signature valid AND covers the purpose header (D2,D3)?
   │ no  → 403 + X-Content-Rules → Exchange  (paid/partner path)
   ▼ yes
fast-path eligible? (allow/deny per D10)
   │ no  → 403 → Exchange   (this bot can still obtain a publisher Biscuit)
   ▼ yes
a free-index term (D1) matches this path?
   │ no  → 403 → Exchange
   ▼ yes
serve the free resource (from CDN cache) + write a free-tier access record (D8)
```

The allow/denylist gates **the fast path, not access.** A denied or non-allowlisted bot is not blocked from the content — it is routed to the normal Exchange path and may still transact (or use a publisher Biscuit, ADR-002). "Serve / don't serve" means "fast-pass / no fast-pass."

The edge function runs on **every** request (CloudFront Lambda@Edge viewer-request, Cloudflare Workers, Fastly Compute all execute before/around cache), so the access record (D8) is complete even when the body is served from cache. This dissolves the cache-vs-record tension: cache the bytes, record the signed request per-hit.

### D7 — Serve the free resource directly; a markdown rendition is an optional enhancement

The fast path serves the **requested free resource directly** (origin passthrough of the same path). No rendition swap is required, and the demonstration confirms a single-request serve works without one. A publisher MAY additionally have ingestion produce an LLM-optimized markdown rendition (WP/HTML → readability extraction → markdown → `content_hash` sha256, `RESOURCE_MUTABILITY_STATIC`) and point the free rule at it; the rendition then yields a clean, hashable artifact for the access record (`ResourceIdentity.content_hash`, ADR-012 D4) and a better payload for the crawler. This is a publisher-side **delivery enhancement** (extending `INGESTION_SOURCE_HTML_CRAWL` / `INGESTION_SOURCE_CMS_API`), **not** a prerequisite for the fast path. The free rule carries an optional `content_hash` / rendition pointer; when absent, the edge serves the origin resource as-is.

### D8 — The free-tier access record (two fidelity tiers)

The fast path records every serve, for an **unmetered** access (no `transaction_id`, no signed-URL HMAC). Two fidelity tiers, both joined to reconciliation:

**Tier 1 — log-line evidence (demonstrated).** The edge emits a structured `pass:free-index` line carrying the requester's `bot_kid` + `Signature-Agent`, the `sig_prefix` of the bot's signature, the declared purpose, the governing `License.id`, the path, and a `req_id` join key. The non-repudiable element is the *bot's own signature* — already verified at serve time; the ledger anchors identity by confirming `bot_kid` is published in the bot's directory. This is what the demo ships and what `ledger.py --free` renders.

**Tier 2 — edge-counter-signed record (full design).** For production reconciliation, promote the line to a record the **edge itself counter-signs** (per-node Ed25519, ADR-012 D2) — a new outcome (e.g. `DELIVERY_OUTCOME_FREE_INDEX_SERVED`) in the ADR-012 schema, adding `record_timestamp`, `edge_node_id`, the WBA key thumbprint (RFC 7638), the `Signature` / `Signature-Input` bytes, `content_hash`, `bytes_sent`, and the edge `record_signature`. Tier 2 adds *edge-side* non-repudiation (the edge attests it served) on top of Tier 1's *bot-side* non-repudiation, and lets the reconciler re-verify bytes rather than only confirm the key is published.

Both tiers sync to the Exchange reconciler in **batch** (ADR-012 D6 polling; ADR-011 join) — **not** fire-and-forget; dropping to counts-only would discard the non-repudiation D3 created. The result is one unified view of accesses + indexing across the paid and free tiers.

### D9 — Onboarding: one declared catalog, two projections; background job owns mutation

A publisher declares its catalog once. Two projections derive from it:

1. **Exchange catalog** → `PushResources` records (pricing, metering, paid terms) — unchanged.
2. **Edge config bundle** → a **path-pattern** ruleset (free patterns minus premium patterns, most-specific-wins; never an enumerated URL list — publishers have millions of URLs) plus an exception list and the allow/denylist (D10), written to the CDN-native edge-data store the edge reads in D5. The fidelity-collapse that derives these patterns + exception list from the high-fidelity catalog is D12.

A **background job** (control plane, not the edge) generates and refreshes the bundle: routinely (daily, and event-driven on `PushResources`) for the ruleset and lists, and via the existing `revocation_url` 300s emergency channel (ADR-003/009) for fast revocation of a compromised crawler key or a turned-abusive bot. Deployment offers two modes, consistent with "the product prepares builds; the operator deploys": (a) the publisher self-deploys the generic edge function + config bundle, or (b) managed deployment via least-privilege CDN delegation (Cloudflare scoped token, Fastly scoped token, AWS cross-account IAM role + external ID — "deploy one worker, write one KV namespace," nothing broader).

### D10 — Allow/denylist semantics, keyed on cryptographic identity

Both lists are supported with explicit precedence: **denylist always wins**; if an allowlist is present, serve the fast path **only** to listed crawlers (minus denylist); if absent, serve **all** validly-signed crawlers (minus denylist). Entries key on **WBA identity** (operator domain via `Signature-Agent` and/or the key thumbprint), never on User-Agent. Lists are seeded from the community verified-bot registry + Cloudflare's verified-bots set and refreshed daily by the D9 background job. Choice of allowlist vs denylist posture is publisher policy, not a system default.

### D11 — Implementation-level, with one targeted standards move

Like ADR-012 D9, this ADR adds **no new `ramp.proto` message** for the fast path — the free-index term already exists (ADR-014) and the edge↔exchange interfaces are internal to the operator's deployment. The single thing that warrants a protocol/standards move is the **signed purpose request component** (D3): there is no standardized bot→publisher signed purpose declaration in either WBA (identity only) or AIPREF (publisher→bot only). RAMP defines an interim request header enforced verifier-side now, and tables the standardization as the WBA-WG ask: "a request-side purpose component, reusing the AIPREF vocabulary, coverable by RFC 9421 `Signature-Input`."

### D12 — The projection collapses catalog fidelity to a minimal rule set; deviations are exclude-only

Content ingestion now produces **high-fidelity, per-resource** terms (ADR-014). The edge can hold only **a few rules**. The D9 background projection therefore *collapses* that fidelity: it finds the largest footprint carrying the plain free-index shape (D1) and expresses it as a minimal set of path patterns (most-specific-wins), then records every resource whose terms deviate as an **exception removed from the fast path**. Exceptions only ever **shrink** the fast set — the projection can withhold the shortcut, never widen access.

Mechanically: broad patterns carry the bulk (`/questions/*` → free-index); a per-URL exception list carries the scattered deviations that do not segregate by path. Both resolve to the same edge outcome for a non-matching request — `403 → Exchange`.

**Example.** Two pushed resources, both `free` for indexing. Resource A is the plain shape → folded into the free pattern, served at the edge in one request. Resource B adds an `ATTRIBUTION` obligation → not the plain shape, so the projection lists it as an exception; the edge does not fast-path it, and it goes through the full RAMP cycle, where the attribution obligation is presented, accepted, and recorded via `UsageReport`.

**Consequence — fast-path coverage is proportional to policy uniformity.** A publisher with one uniform free-index policy gets near-total edge coverage; one who attaches bespoke obligations/scopes/restrictions per resource gets more exceptions and less shortcut. This is a healthy incentive — the simpler the free grant, the cheaper it is to serve at scale — and the projection should surface it: report exception count (and the resulting fast-path coverage ratio) per domain at onboarding so a publisher sees the cost of fidelity.

#### Amendment (2026-09-02) — the free fast path has no signed URL at all

D8 describes a free-tier access as carrying "no `transaction_id`, no signed-URL HMAC". No
signed URL in this system has ever carried an HMAC. URL signing is asymmetric and selected
per tenant by `tenants.signing_scheme`: Ed25519 verified by the edge worker, or RSA verified
natively by CloudFront. The delivery endpoint holds public keys only. See the 2026-09-02
amendment to **ADR-012** for the same correction across that ADR's three decisions.

The correction to D8 is stronger than swapping one primitive for another. What distinguishes
a free-index serve is not that its signed URL uses a weaker signature — it is that **there is
no signed URL**. The fast path is entered before any URL verification happens, which is why
the edge branches on the presence of a `sig` parameter first: a request without one is a
candidate for the free path or the bot gate, and never reaches the verifier. D8's substance
is unaffected; the phrase to read is "no signed URL", and the reason the free record's
evidence rests on the bot's own RFC 9421 signature rather than on anything the Exchange
minted is exactly that no Exchange-minted artifact exists on this path.

---

## Realization status

The reference implementation (`feature/free-index-path`, PR #2) demonstrates the design end to end while deliberately stubbing the parts that need production infrastructure.

**The artifacts in the "Realized by" column live on that branch, not in this repository** — only `app.ts` exists here. They are named as they appear there:

| Decision | Status | Realized by |
|---|---|---|
| D1 term-driven eligibility | Demonstrated (as static rules) | `freerule.ts` |
| D2 WBA identity, offline verify | **Demonstrated — real RFC 9421 / Ed25519** | `wba.ts`, `wba-crawl.py` |
| D3 signed-purpose coverage keystone | **Demonstrated** | `wba.ts` (`coverageCheck`); header `X-Intended-Use` |
| D4 response labeling | Partial — Hono inline; CDN deferred to origin-response | `app.ts` |
| D5 edge pure-read | Demonstrated | `app.ts`, `cloudfront-edge.ts` |
| D6 decision ladder (fast-path-first) | Demonstrated | `cloudfront-edge.ts`, `app.ts` |
| D7 direct serve (rendition optional) | Demonstrated — direct serve, no rendition | `cloudfront-edge.ts` |
| D8 access record | Tier 1 (log-line) demonstrated; Tier 2 (counter-signed) design-only | `ledger_free.py`, `ledger.py --free/--compare` |
| D9 catalog→config projection | Design-only — config hand-authored for the demo | `edge-config.demo.mjs` |
| D10 allow/denylist | Design-only — single baked bot key | `edge-config.demo.mjs` |
| D11 implementation-level + WG ask | Holds — no proto change | — |
| D12 fidelity collapse | Design-only — static table stands in for the projection | `freerule.ts` |

The demonstrated core is the load-bearing claim: a real WBA signature with a covered purpose serves free content in one request and is recorded; the paid 6-row chain visibly collapses to a 2-row free chain (`ledger.py --compare`). The design-only rows are control-plane / reconciliation surface, not new protocol.

---

## Cross-system impact map

| Area | Existing artifact | Change this ADR implies |
|---|---|---|
| Licensing core | ADR-014 `LicenseTerm` | No shape change. The fast path is triggered by a term class already expressible. Free-index term becomes the load-bearing input. |
| Edge function | `src/edge` (Hono, multi-runtime) | New read-only fast-path branch (D1–D6) ahead of the existing signed-URL verification and barking-dog 403. WBA verification + signature-coverage check + term/ruleset match. |
| Edge config | bot-pattern KV (bot-detection.mdx) | Generalized to a per-publisher config bundle (collapsed ruleset + exception list + allow/denylist), written by the control plane, read by the edge (D5/D9/D10/D12). |
| Ingestion projection | ADR-014 high-fidelity per-resource terms | New collapse step (D12): fidelity → minimal edge rules + exclude-only exceptions; reports fast-path coverage ratio per domain. |
| Identity | ADR-009; `WBAFile.keys`, `JsonWebKey` | Adds WBA crawler identity as a verified principal at the edge. Crawler keys resolved via `Signature-Agent` directory, distinct from agent request-signing keys. |
| Biscuit model | ADR-002 two-Biscuit | Fast path is the zero-credential tier; the publisher Biscuit remains the fallthrough for non-fast-pass bots and for metered/paid use. Tiers stay unmixed (Out of scope). |
| Ingestion (optional) | `INGESTION_SOURCE_HTML_CRAWL/CMS_API` | Optional render-and-host stage (D7) for an LLM-markdown rendition; not required — the edge serves the origin resource directly by default. |
| Delivery log | ADR-012 | Unmetered access record (D8): Tier 1 log-line (demonstrated), Tier 2 counter-signed variant (design); same retention + polling transport. |
| Reconciliation | ADR-011 | Free-tier records join the three-way reconciliation as a fourth, unmetered witness stream → unified accesses+indexing view. |
| Revocation | ADR-003/009 `WBAFile.revocation_url` | Reused for emergency crawler-key / fast-pass revocation (D9). |
| Protocol / standards | `ramp.proto` | No new message (D11). One WG ask: signed purpose request component. |

---

## Out of scope

- **Quotas / metered free access.** Any per-crawler cap reintroduces shared mutable state and a round-trip, defeating the edge-local property. Metered access is the Biscuit/Exchange tier; the free tier has no quota by construction.
- **Non-WBA crawler identity** on the fast path. Unsigned bots get the barking-dog 403 → Exchange.
- **LIVE / streaming** resources (inherits ADR-012 D4's LIVE deferral).
- **Markdown rendering fidelity SLA** and per-CDN edge-data adapter abstraction — defer until a second runtime ships the fast path in production (mirror ADR-012's deferral discipline).
- **Protocol-level standardization** of the purpose component beyond tabling it to the WG.

---

## Consequences

### Positive

- Kills the dominant adoption objection: the high-volume case (index crawl of free content) becomes a single cached `GET` + an Ed25519 header — same cost as the open web — while monetized use keeps the full transaction. RAMP becomes strictly cheaper than the status quo for the common case.
- Every fast-path serve leaves a **signed, non-repudiable** access record; the publisher gets a unified ledger of who indexed what under which license, despite zero round-trips.
- Reuses WBA (identity), AIPREF (publisher label), data-labels TDL (license identity), ADR-011/012 (reconciliation + log), and `WBAFile.revocation_url` (revocation). Almost no net-new trust surface.
- Edge stays pure-read and cacheable; control-plane mutation is isolated.

### Negative

- **T18 (selective enforcement)** becomes operational reality the moment the edge makes allow/deny decisions. Mitigation: the decision is term-driven and every serve is signature-logged, so it is auditable rather than opaque — but the protocol still does not *prevent* a publisher serving some and not others.
- Acceptance via response label is browsewrap; the whole non-repudiation claim rests on D3's signed purpose header actually being covered by the signature. Verifier-side enforcement of `Signature-Input` coverage is therefore load-bearing, not optional.
- Optional ingestion cost: a publisher that opts into the markdown rendition (D7) must generate it and keep its `content_hash` current. The default direct-serve path avoids this.
- Config staleness window: routine refresh is daily; emergency revocation rides the 300s `revocation_url` poll. A fast-pass granted against stale config is the publisher's bounded business risk (same stance as the protocol's revocation caching contract).

### Rejected alternatives

- **Actor/User-Agent-driven gating** ("is this a real crawler?") — inherits a maintained allowlist and authorizes free serves on spoofable signals. Replaced by term-driven + WBA-cryptographic gating (D1/D2).
- **A sibling protocol** for crawl access — forks the identity story exactly as WBA converges and discards RAMP's commercial-layer differentiation. This is a RAMP edge profile on top of WBA, not a peer (D11).
- **Per-publisher generated function code** — combinatorial maintenance (N publishers × 3 runtimes × versions). Replaced by one generic function + per-publisher config data (D5/D9).
- **Fire-and-forget telemetry** — discards the signed evidence. Replaced by batch sync of signed records (D8).
- **Inventing a RAMP-specific purpose vocabulary** — replaced by reusing AIPREF/RSL tokens already aliased in ADR-014 (D3).
- **Standardizing the fast path in `ramp.proto`** — excludes CDN-native variation and is unnecessary; the term already exists (D11).

---

## Open questions

1. **Standardization of the purpose component, and whether to cover the license id.** The header is `X-Intended-Use` and the covered set is `(@authority, @path, X-Intended-Use)` — settled for the implementation. Open: whether to standardize the component through the WG / align it with an AIPREF request-side construct, and whether to add the governing license id to the covered set so the bot co-signs the *specific* license rather than only the purpose.
2. **Optional markdown rendition (D7).** If a publisher opts in: public URL (maximally cacheable) vs short-TTL signed URL; where the rendition lives relative to the origin; how `content_hash` updates propagate on edits. Moot for the direct-serve default.
3. **Promoting the record from Tier 1 to Tier 2 (D8).** When to add the edge counter-signature as a `DELIVERY_OUTCOME_FREE_INDEX_SERVED` variant in ADR-012's schema (one log, one reconciler) vs leaving log-line evidence sufficient for early production.

---

## References

- ADR-002 — two-Biscuit model (fallthrough path for non-fast-pass bots).
- ADR-003 / ADR-009 — key rotation / revocation; identity boundary; `revocation_url` reuse.
- ADR-011 — three-way reconciliation (free-tier records as an added witness).
- ADR-012 — Edge Delivery-Log contract (record signing, transport, retention reused by D8).
- ADR-014 — Universal Licensing Core (the free-index term; License identity; AIPREF/RSL vocab aliases).
- `ramp.proto` (module `github.com/RAMP-Protocol/protocol`) — `LicenseTerm`, `Restriction{kind: FUNCTION}` (incl. `crawl`/`ai-index`/`search`), `Pricing{model: FREE, metering: NONE}`, `License{uri,id,immutable}`, `ResourceIdentity.content_hash`, `WBAFile.keys` / `WBAFile.revocation_url`, `JsonWebKey`.
- `website/.../protocol/authentication.mdx` §WebBotAuth; `components/edge-function/bot-detection.mdx`; `protocol/discovery-paths.mdx` (Path A/C).
- [draft-meunier-web-bot-auth-architecture-02](https://datatracker.ietf.org/doc/html/draft-meunier-web-bot-auth-architecture-02); draft-meunier-http-message-signatures-directory (`Signature-Agent`).
- [RFC 9421 — HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421).
- [draft-ietf-aipref-vocab-04](https://www.ietf.org/archive/id/draft-ietf-aipref-vocab-04.html); [draft-ietf-aipref-attach-04](https://datatracker.ietf.org/doc/html/draft-ietf-aipref-attach-04) (`Content-Usage`).
- [Cloudflare — Verified Bots with cryptography](https://blog.cloudflare.com/verified-bots-with-cryptography/).
- Standards: the WBA-WG ask — a request-side signed purpose component.
- Realization: reference-implementation branch `feature/free-index-path` (PR #2). On that branch the edge carries wba.ts, freerule.ts, cloudfront-edge.ts and app.ts, the ledger and crawler tooling carries wba-crawl.py and ledger_free.py alongside `ledger.py --free/--compare`, the Lambda@Edge bundler is build-lambda-edge.mjs, and the walkthrough is the free-index handoff note. None of these exist in this repository.

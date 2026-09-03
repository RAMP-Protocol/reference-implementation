# ADR-016 — Edge-Resolved Capability Access (entitlement biscuits at the edge)

**Status:** Proposed (2026-06-16)
**Realisation (2026-07-29):** Not built. The edge does not resolve or verify entitlement biscuits — no biscuit code exists under `src/edge/src/`. Nothing in the handed-over build depends on this ADR; it describes intended future work.
**Builds on:** ADR-002 (Entitlement-Biscuit Model), ADR-005 (Biscuit transport + canonical binding), ADR-006 (Broker intermediation), ADR-012 (Edge Delivery-Log), ADR-014 (Universal Licensing Core), ADR-015 (Edge Free-Index Fast Path)
Reopens the deferred scope-verification work (the ADR-014 "TRUST CAVEAT"), and re-introduces a layer removed earlier. Related work: identity / Web Bot Auth, and the signed purpose component.

---

## Context

ADR-015 lets a crawler fetch content from the edge **without an Exchange transaction**, but only for the *plain free-index* term: `Pricing{model:FREE, metering:NONE}`, a single `Restriction{kind:FUNCTION}` ⊆ {crawl, ai-index, search}, no quota, no obligation, and **`scopes` empty**. The scopes-empty requirement is load-bearing and explicit: a non-empty scope "would require resolving a Biscuit the edge can't do," so anything that isn't public falls through to the full round-trip.

Two facts make that boundary too conservative for a large, practical class of access:

1. **The capability already exists in design, and resolving it is local compute, not a round-trip.** ADR-002 defines a single **entitlement biscuit**: an authority block signed by the **resource owner** (facts: `resource_owner`, `subscriber_org`, `buyer_delegation_pubkey`, `grants`, `valid_until`, and `check if signed_by(buyer_delegation_pubkey)`), plus a **mandatory per-request attenuation** signed by the buyer's (principal's) delegation key (≤10-min TTL, subject-bound). This is a *self-rooting chain*: the only out-of-band key needed to verify it is the resource owner's. The principal and agent keys are delivered *inside* the chain, so verifying it is three signature checks and a scope-containment test.

    **The zero-I/O claim rests on a premise this repository does not currently satisfy.** It was written assuming the edge already holds the resource owner's key from the well-known manifest. It does not: the manifest carries no keys at all, and the key the edge verifies signed URLs against is the *Exchange's*, resolved from its Web Bot Auth directory (`EXCHANGE_WBA_URL`) or pre-provisioned. Reaching the resource owner's key would be a second directory fetch that nothing wires today. Either that fetch is added and cached — at which point the cost is a cache miss, not zero — or the resource owner's key is provisioned alongside the Exchange's. This ADR does not decide which, and the argument above should not be read as established until it does.

2. **The thing that would make scoped edge serving safe is exactly the thing currently missing.** Today requester scopes are **self-declared and unverified** — `src/exchange/internal/service/termselect.go` (and ADR-014) state plainly that scope coverage is "an honest projection of intent, NOT yet an authorization boundary: an agent could claim any scope." The Exchange-side Biscuit verifier that once closed this (Datalog gates A–E, per-block scope intersection on `biscuit-v2`) was **removed**, and so was the canonical request-binding layer it relied on. Only RFC 9421 signing (`internal/httpsig`) remains; the carriage and binding pieces this ADR would build on no longer exist and would have to be rebuilt.

Meanwhile a broad set of real use cases is **pre-negotiated and unmetered** — flat/time-boxed subscriptions, "index everything under license L," fair-use/attribution research access, distributor library access. For these the protocol's round-trip (`DiscoverResources → ExecuteTransaction → signed URL → fetch → ReportUsage`; Path F even sets `rate=0` but still runs the full cycle) is pure latency: there is no price to settle, no quota to decrement, no offer to negotiate that wasn't already negotiated when the grant was issued.

This ADR decides to **resolve the entitlement biscuit at the edge** so those grants are served directly — generalizing ADR-015 from "public, no credential" to "scoped, credentialed, flat/unmetered" — while keeping everything that *needs* shared state or live negotiation off the hot path. The organizing principle is a clean **control-plane / data-plane split**: relationships, discovery, offer selection, grant issuance, and key exchange are control-plane (slow, online, directory-based); the hot path carries only a self-contained, pre-verified artifact and does pure compute.

---

## Decision

### D1 — The edge resolves the entitlement biscuit, lifting the fast path from public to scoped flat/unmetered terms

The edge MAY serve a resource **without an Exchange transaction** iff:

- the matched `LicenseTerm` is **settlement-free at request time** — `Pricing.model ∈ {FREE, FLAT}` with `Pricing.metering = NONE`, **no `Quota`**, **no blocking `Obligation`**; AND
- either the term's `scopes` are empty (the ADR-015 public free-index case — the degenerate, no-credential instance of this rule), **or** the request carries a valid entitlement biscuit (D2) whose granted scopes **AND-cover** the term's `scopes` (ADR-014 coverage semantics: `dist:*` covers `dist:US`, `*` covers all, empty = public).

This supersedes ADR-015 D1's "`scopes` empty" precondition for the credentialed case. The edge enforces exactly this rule; it does not interpret obligations, quotas, geographies, or user-types — their presence routes full-cycle (D7), it does not evaluate them.

### D2 — The chain self-roots in the resource-owner key; the edge needs no key registry and makes no network call

The edge's only trust anchor is the **resource-owner (publisher) signing key**, already in its config. Verification walks the chain delivered in the token:

1. Resource-owner key (local) verifies the **authority block** → yields the granted `scopes`, `valid_until`, and the principal's `buyer_delegation_pubkey`.
2. The **principal delegation key** (from step 1) verifies the **attenuation block** → yields the TTL and the agent binding.
3. The **agent key** (from step 2) verifies the **request signature** (D3).

Principal and agent keys arrive *inside* blocks signed by keys the edge already trusts, so there is no JWKS fetch, no directory lookup, and no "all parties' keys" problem on the hot path.

### D3 — The agent's identity is the request signature (holder-of-key); `.well-known` / Web Bot Auth is control-plane only

The agent proves it is the bound delegate by **signing the request** (RFC 9421, the verification the edge already performs for signed URLs). The attenuation binds to the agent's request-signing key by **RFC 7638 JWK Thumbprint** — the JWT-less variant of ADR-002's subject binding, identical to ADR-009/ADR-012's `agent_identity_hash`. *Appending a biscuit block is not an identity proof* (any holder can attenuate); the request signature is. The directory exchanges (principal learning the agent key to bind it; publisher verifying the principal at issuance; key rotation; biscuit reissuance) happen at issuance/rotation time over `.well-known`, **never at request verification**. Web Bot Auth thus moves entirely to the control plane; the data plane keeps only the signature-as-possession-proof.

### D4 — The chain-linkage invariant is mandatory

Verification MUST require that **the signer of each block is the key named by the previous block**: resource-owner → authority names `buyer_delegation_pubkey` → principal signs attenuation → attenuation names the agent thumbprint → agent signs the request. A block bearing a valid signature by a key **not named upstream** is rejected. (ADR-002's `check if signed_by(buyer_delegation_pubkey)` enforces the authority→attenuation link; the agent link is the thumbprint match against the request signature.) Checking "is this block validly signed by *some* key it declares" instead of "by the key the parent *named*" is a full privilege-escalation hole and is the single most likely way to implement this wrong.

### D5 — The hot path is pure-read and pure-compute; the access record is the only side effect

At request time the edge: verifies the chain (D2/D4), verifies the request signature (D3), checks the requested resource ∈ granted scopes ∩ a settlement-free term (D1), and serves via origin passthrough. **No writes, no network calls, no shared mutable state.** Chain verification for a given attenuation MAY be cached within its TTL, so per-fetch cost collapses to roughly one Ed25519 verify (the request) + a scope-containment check + one log append. This is strictly leaner than ADR-015's free-index path, which still fetches the bot JWKS on warmup.

### D6 — The signed fetch *is* the usage record; it replaces `ReportUsage` for everything observable at delivery

`ReportUsage` does two jobs: (a) establish the access event, and (b) attest post-delivery behavior. Job (a) is fully captured by the edge record and captured better: every served fetch produces a delivery record (a new outcome `DELIVERY_OUTCOME_CAPABILITY_SERVED` in the ADR-012 schema, alongside ADR-015 D8's free-index variant) carrying the agent thumbprint, the grant identity (authority + attenuation references), the resource, `content_hash`, and the **bot's own request-signature bytes**. Because each entry is signed by the agent, it is **non-repudiable by the bot and unforgeable by the publisher** — so no separate `ReportUsage` call is needed for the access event, and "failed to report within the deadline" cannot occur (the report *is* the fetch). Records batch-sync to the reconciler (ADR-012 D6 transport; ADR-011 join). Active `ReportUsage` remains required **only** for job (b) — post-delivery obligations the fetch cannot observe (downstream-use counts, attribution placement).

### D7 — Tier boundary: the edge handles "nothing to settle"; metered and post-delivery-obligation terms keep the Exchange in the path

The edge serves only terms with **no request-time shared state**: `FREE` (public) and `FLAT` + `metering:NONE` (time-boxed prepaid). A term carrying a `Quota` or `Pricing.metering ≠ NONE` decrements a counter shared across edge POPs and **cannot** be edge-local — it routes to the Exchange. `metering:NONE` vs metered therefore becomes a first-class, load-bearing property of the grant: it is the bit that decides edge-vs-Exchange.

### D8 — Pre-disclosed consent collapses the *agent-visible* round-trip for metered terms — but not the meter

For metered terms, an agent that already consents may present a consent referencing a **content-addressed terms hash** ("I accept the offer matching terms `T`"). The request routes to the Exchange, which checks `current_terms_hash == T`: on **match**, it executes (preserving write-before-deliver) and returns content via the existing signed-URL redirect in a single hop; on **mismatch**, the terms have moved and it falls back to presenting the new offer (a real round-trip). The metered execute MUST be **idempotent per consent nonce** (or the signed URL one-time), because money moves. This collapses discovery, never the meter — the Exchange stays in the path to move the counter.

### D9 — Enforcement is graceful via TTL non-renewal at the owning layer; hard invalidation is emergency-only

Every layer's grant has a TTL, and enforcement is *non-renewal* at the layer that owns the relationship:

- **Agent** delinquent/compromised → the principal stops minting the short-TTL attenuation; access lapses in minutes and recovers on fix. (Cheap, self-healing — the common case.)
- **Principal** delinquent → the resource owner stops renewing the authority grant (give the authority block a moderate TTL); for a *compromised* principal key, push a denylist over the existing `revocation_url` 300 s channel (ADR-003/009).
- **Resource-owner root key** is the one catastrophic anchor — rotate per ADR-003; a botched rotation breaks all verification at once.

A reporting-obligation lapse (D6's post-delivery tier) is handled by non-renewal, **not** by hostile biscuit invalidation — invalidation is reserved for compromise/abuse, not a config error.

### D10 — Edge does *containment*; Exchange/Broker does *search*. This is the bright line that keeps the boundary from drifting

The edge only ever evaluates **membership against information in hand** — `{the request, its biscuit, the static free-rules, the resource-owner key}`. It **never searches the offer space.** The biscuit is the *frozen result of a prior search*, carried so the edge can do a present containment test. The edge has exactly **three verdicts**: *serve-via-free-rule* (public, ADR-015), *serve-via-grant* (this ADR — containment in the biscuit), or *route-to-Exchange* (anything else — no covering grant, non-uniform offer, or metered). Offer discovery and best-offer selection stay whole at the Broker (Path B: fan-out, dedup by `ResourceIdentity`, rank by `unit_cost`); the agent self-selects a term (ADR-014) and obtains a biscuit, then presents it. The operational test: *does deciding this request need anything outside the in-hand set (the offer catalog, pricing, a counter, another principal's state)? No → edge; Yes → Exchange.*

### D11 — Ingestion projects the edge config as *data*, not code; the projection is the security-critical surface

The edge function is generic, shared, and audited once. Per-publisher ingestion emits only **data** — the free-rule path patterns, the scope→term map, and the resource-owner trust-anchor key — written to the CDN-native edge-data store by the background job (ADR-015 D9). Because the crypto is airtight, the place a mistake leaks content is now the **projection**: gated content mapped into a public/free scope, or a stale/wrong anchor key, and the edge will *correctly verify its way into serving the wrong thing*. The projection MUST therefore be **signed config** and obey ADR-015 D12's exclude-only discipline (a per-resource deviation may only *shrink* the served set, never widen it). No bespoke per-publisher function code (that is N publishers × runtimes × versions of audit surface).

### D12 — Protocol surface: reuse what exists; the net-new is verification + a formal edge access record

Intended to be reused as-is: the entitlement biscuit (`Delegation.token_format = "biscuit-v2"`, `scopes[]`, `expires_at`, `max_accesses`), its three-tier carriage (ADR-005), the canonical request binding (Gate F), the authority+attenuation structure (ADR-002), and RFC 9421 request signing (`internal/httpsig`). **Only the last of these still exists** — the biscuit carriage and the canonical binding were deleted, so this ADR's cost estimate is understated: they would have to be rebuilt, not reused. **Net-new:**

- **Edge-side biscuit *verification*** — re-introduce a `biscuit-v2` verifier with the D4 chain-linkage check and the scope-coverage test, deployed **at the edge** rather than the Exchange (the previously-removed code, re-homed and re-scoped). This closes the deferred "TRUST CAVEAT."
- **A formal edge access-record message** — ADR-012's delivery record is design-only (no proto message, no implementation today); this ADR depends on it existing, with the `DELIVERY_OUTCOME_CAPABILITY_SERVED` outcome.

No new negotiation RPC is required. The one open standards item is the signed purpose component (`X-Intended-Use`), which the credentialed path largely subsumes (the grant already pins permitted functions); it remains relevant for the public free-index path.

### D13 — Binding the post-delivery report to the access record; reconciliation drives non-renewal

D6 splits `ReportUsage` into two jobs; this pins how job (b) — the post-delivery obligation the fetch cannot observe (downstream use, e.g. grounding an answer) — is **bound** to the served fetch and **enforced**.

- **A per-access identifier joins the two.** When the edge (or the publisher's own server — the edge is not required) serves a biscuit-authorized fetch, it issues a unique **access id** (an "offer id" in the agent's terms) that (i) is written into the edge access record (D6) and (ii) the agent **echoes in any post-delivery `ReportUsage`**. On the wire this is the existing `UsageReport.transaction_id` (which already keys usage alongside `billing_id`) — **no new proto field**. The reconciler joins fetch-record ↔ report by this id (ADR-011 join). The served response MAY also carry the resource's licensing terms / a license reference (RSL), but for this path they are redundant: the biscuit *is* the agreement under which they were issued.
- **Enforcement is reconciliation-driven and deferred — by design.** This path **cannot enforce `ReportUsage` in real time**: the downstream use happens off-platform. The control is the reconciler (D6 transport; a batch cadence of hours/days, never real-time) detecting a served access with no matching post-delivery report and triggering **non-renewal at the owning layer** (D9) — the principal/owner stops renewing the grant, and access lapses. Hard biscuit invalidation stays emergency-only (D9). The accepted cost is a detection latency bounded by the reconciliation cadence.
- **The request declares the use; the report confirms it.** The signed request states the intended use (the grant already pins permitted functions, D12); the post-delivery `ReportUsage`, keyed by the access id, confirms it for reconciliation.

This reserves the edge fast path for **simple, externally-agreed, unmetered** access (D7): you trade real-time enforcement for one-hop latency, with the reconciler + non-renewal as the backstop.

---

## Consequences

### Positive

- **Unmetered, scoped access serves like static content.** No round-trip, no shared state, no I/O on the hot path — RAMP-gated flat/free content costs about what serving static content costs. The round-trip's *coordination* is removed, not just its latency.
- **The scope-trust gap closes where it matters.** The deferred "an attacker could claim any scope" caveat is resolved by an offline, edge-verifiable chain rooted in the resource-owner key — without re-coupling the Exchange into every fetch.
- **Attribution gets stronger, not weaker.** Every fetch is a contemporaneous, signed, terms-bound event that the bot cannot repudiate and the publisher cannot fabricate — replacing a later self-report the bot could skip.
- **A clean key-risk gradient.** A stolen *token* is worthless (holder-of-key). A stolen *agent key* is TTL-bounded and self-heals on the next non-renewal. The *principal key* (the crown jewel) lives in the keychain doing only control-plane signing and is the sole hard-revocation case. The expensive secret is kept off the exposed surface by construction.
- **Graceful, recoverable enforcement** via per-layer TTL non-renewal, with hostile invalidation reserved for genuine compromise.

### Negative

- **The config projection becomes a content-leak surface** (D11): the crypto can be perfect and a mis-classified scope still gives content away. Requires signed config + exclude-only discipline + review of what ingestion marks public.
- **A new online dependency: the principal's minting service.** Short-TTL attenuations mean the agent has a recurring control-plane heartbeat to the principal; the TTL is the revocation-speed-vs-availability dial.
- **Re-introduces a previously-removed verification layer** and a `biscuit-v2` library dependency — now at the edge, where runtime constraints (e.g. Lambda@Edge) and multi-runtime parity (Cloudflare/Fastly/CloudFront) apply.
- **Staleness window.** A pre-pinned grant runs under terms the publisher may have since changed, bounded by the authority TTL and the 300 s invalidation channel — the publisher is not in real-time control of each access.
- **T18 (selective enforcement)** remains operational reality: the edge decides who is served, but every serve is signature-logged, so it is auditable rather than opaque.

---

## Out of scope

- **Metered / quota'd access at the edge.** Any per-grant counter is shared mutable state and routes to the Exchange (D7). The full mechanics of the D8 metered fast-track (idempotency keying, redirect delivery) are a separate decision.
- **Biscuit Datalog fact-set extensions** beyond the ADR-002 set (`scope`, `max_spend_cents`, `max_accesses`, `quota_period`, `expires`, `signed_by`).
- **Non-WBA / non-signature agent identity** on the fast path (inherits ADR-015: unsigned bots get the barking-dog 403 → Exchange).
- **LIVE / streaming resources** (inherits ADR-012 D4's LIVE deferral).
- **Standardizing the purpose component** beyond tabling it to the WG.

---

## Open questions

1. **Where does scope-coverage verification live** — edge-only (this ADR), or also re-instated at the Exchange for the full-cycle path (the deferred Exchange-side check)? If both, do they share one `biscuit-v2` verifier, and does it live in `internal/` for reuse across `src/edge` and `src/exchange`?
2. **Is the signed `X-Intended-Use` purpose header needed on the credentialed path at all**, given the grant already pins permitted functions — or only on the public free-index path?
3. **Authority-block TTL: static-with-denylist vs moderate-TTL-with-renewal** — i.e. the principal-level graceful-enforcement knob (D9). What default?
4. **Attenuation reuse window vs per-fetch minting**, and the principal signing-service availability/throughput trade-off (D5). Recommended TTL band?
5. **Formalize the edge access record as a wire message?** ADR-012's record is design-only; adopting it as a proto `DeliveryLog`/access-record message (with `content_hash` propagation for `STATIC` resources) is a prerequisite for D6/D12.
6. **Re-introducing `biscuit-v2` verification**: which library (the removed code used `biscuit-go/v2`), and are ADR-002's resource-owner-authority + buyer-signed-attenuation expressible as that library's blocks/third-party blocks, or do they need the custom RAMP fact-set on top?
7. **Reconciliation join.** An edge-only capability serve has no `transaction_id`; how do its records join ADR-011's three-way reconciliation — on the grant id + agent thumbprint (as ADR-015 D8 joins on `req_id`)?
8. **D8 metered fast-track idempotency** — consent nonce vs one-time signed URL, and where the dedup state lives.
9. **Biscuit confidentiality.** The token is signed, not encrypted, and reveals the licensing relationship (who licenses what from whom) to any intermediary or edge log. Acceptable, or minimize/wrap?
10. **Relationship to `feature/broker-multiexchange`.** That branch issues broker-signed offer echo-backs (`OfferCapability`, *not* a capability token) across RAMP + non-RAMP marketplaces. How does a bridged (non-RAMP) offer become an edge-resolvable grant — does the broker mint an entitlement biscuit on the publisher's behalf, and if so under whose root key?

---

## References

- **ADR-002** — Entitlement-Biscuit Model (the authority + mandatory-attenuation chain this ADR resolves at the edge).
- **ADR-005** — Biscuit transport carriage + canonical-form request binding (Gate F).
- **ADR-006** — Broker intermediation (`authorized_intermediaries`, Gate G) — the intermediation model the issuance path uses.
- **ADR-003 / ADR-009** — key rotation/revocation; identity boundary; `agent_identity_hash` = RFC 7638 Thumbprint; `WBAFile.revocation_url`.
- **ADR-011 / ADR-012** — three-way reconciliation; Edge Delivery-Log (the access record this ADR extends).
- **ADR-014** — Universal Licensing Core (`LicenseTerm`, `Pricing`, `Restriction`, `scopes` AND-coverage; the 2026-06-15 scope-only / no-requester-attribute-filtering amendment; the scope TRUST CAVEAT).
- **ADR-015** — Edge Free-Index Fast Path (the public, no-credential predecessor this generalizes; D8 access record; D9 projection; D12 exclude-only collapse).
- Protocol: `ramp.proto` (module `github.com/RAMP-Protocol/protocol`) — `Delegation{token_format:"biscuit-v2", scopes[], expires_at, max_accesses, revocation_uri}`, `Requester{scopes[], delegation}`, `LicenseTerm`, `Pricing{model, metering}`, `WBAFile.keys`, `JsonWebKey`. Protocol docs: discovery-paths (Path B/F), authentication (signed-URL identity binding), Web Bot Auth compatibility.
- `internal/httpsig` — the RFC 9421 signing stack, the one piece of the old carriage layer still present. The entitlement-carriage and canonical-binding packages were deleted and would have to be rebuilt. `src/exchange/internal/service/termselect.go` — the scope TRUST CAVEAT, in the doc comment on `selectTerms`.
- Prior-art research on delegation standards. The removed implementation is recoverable from git history.
- Related work: scope-only filtering, identity / WBA, the signed purpose component, the licensing core, and the security review.

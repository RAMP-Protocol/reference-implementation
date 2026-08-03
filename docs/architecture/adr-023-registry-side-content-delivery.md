# ADR-023 — Registry-Side Content Delivery for Custodial Agents

**Status:** Accepted (2026-07-29)
**Builds on:** ADR-013 (agent-key presentation, offline delivery-URL binding), ADR-017 (agent identity & registration), ADR-009 (identity boundary), ADR-012 (edge delivery log), ADR-020 (RAMP SDK layered libraries).
**Supersedes:** ADR-013's 2026-07-27 amendment (enforcement hardcoded OFF).

---

## Context

Two decisions taken separately collided.

**ADR-013** binds a signed delivery URL to the RFC 7638 thumbprint of the key that signed the offer acceptance, and has a capable edge refuse any fetcher that cannot prove possession of that key. The property bought is stated in D3: verifying the signature *without* the thumbprint check "lets any actor present their own key plus a valid self-signature and fetch." A stolen URL is worthless without the key.

**ADR-017** puts the agent's private key in the registry's custody. An SDK-less agent signs in with OAuth, and the registry signs RAMP requests on its behalf with a key the agent never sees.

Composed, they deadlock. The registry signs the acceptance, so the Exchange binds the URL to the *registry-custodied* key; `ramp_execute` hands the agent a URL; the agent has no key and cannot produce the proof. Every URL issued through the registry flow could only ever be used by the registry itself, and every agent fetch got 403.

This was not a bug in either component. It was the intersection of "the registry keeps the key" and "the caller must prove it holds the key".

An interim fix (2026-07-27) hardcoded edge enforcement OFF and deleted the switch, which unblocked agents at the cost of the property: delivery URLs became bearer credentials on every edge, and the amendment said so plainly. It named this decision as its terminator.

The five options weighed were: **A** an agent-generated throwaway key attested by the registry; **B** the registry as a remote signing oracle; **C** the registry fetches the content itself; **D** leave enforcement off (the interim); **E** hardened bearer with one-time-use URLs.

---

## Decision

### D1 — The registry fetches the content; the agent does not

The identity service retrieves the licensed bytes itself, presenting the custodied key as proof of possession, and hands the bytes to the agent over MCP.

The deadlock dissolves because the constraint was never "nobody can produce the proof" — it was "the *agent* cannot produce the proof". The registry can: it holds the key. Moving the fetch to where the key already lives makes the proof producible by construction, with no change to the protocol, the Exchange, the edge's contract, or any agent client.

**Why not A (agent-held throwaway key, attested by the registry).** ADR-013's Context fixes the edge as verifying **fully offline, no JWKS fetch**. An attestation binding a throwaway key would have to be verified by the edge; an attestation the edge cannot check is not a binding, and making it checkable means giving the edge a live trust path back to the registry — trading away the offline property that ADR-013 exists to provide. It is also the widest change of the five: proto contract, Exchange, registry, and every agent client would need key generation and request signing.

**Why not B (remote signing oracle).** An endpoint that signs whatever it is asked to sign is a signing oracle whose own authentication must be at least as strong as the property it protects, and it lands the registry on the read hot path with an extra round trip per fetch. C puts the registry on the same path but asks it to do something narrow and auditable — fetch this URL for this authenticated agent — rather than to sign arbitrary bytes.

**Why not D or E.** Both settle for a bearer URL. D is what is being replaced. E needs replay state on all three edge runtimes, which ADR-013 already deferred as requiring shared edge state, and it complicates retries and range requests. Neither restores D3.

**What C costs, stated plainly.** The registry now transits content it does not license. That is bandwidth, latency, and a blast radius: a compromised registry could already impersonate every custodied agent, but it can now also read their content in flight. It is also an operator question about handling licensed material, not merely a technical one. The agent additionally loses its own network path and cache. These are accepted; the custody model already concentrates this trust, and D1 does not widen *who* is trusted, only *what* passes through them.

### D2 — The fetch is eager, inside `ramp_execute`

The content is fetched during the tool call that licenses it, not on a later request.

Nothing then has to be stored between calls: no cache, no handle table, no expiry sweep, and no second delivery for the edge's log to record (ADR-012 counts one delivery per fetch, so a lazy re-fetch would double-count a single purchase and corrupt reconciliation). It also minimises the rotation window in D6 — the authenticated identity is on the context only for the duration of the call, which is exactly when the key must be resolved.

The cost is that an agent pays the fetch latency for every licensed item, including ones it may not read.

### D3 — Both the bytes and the URL are returned; nothing is persisted

`ramp_execute` returns the content as MCP embedded resources alongside the unchanged `retrieval_endpoint` per item.

The URL is kept because it remains the item's delivery identity — it is what `transaction_log` records, what reconciliation joins on, and what an agent can retry with if the service's own fetch failed. The bytes ride as a **blob** whatever the media type: the SDK's text field is a Go string, and `encoding/json` silently replaces invalid UTF-8 rather than erroring, which would corrupt paid-for content with no signal. The media type travels beside the blob so a client decodes with its own charset handling.

**A failed fetch does not fail the call.** By the time the fetch runs, the Exchange has charged. Refusing the result would bill the agent for content it did not receive *and* withhold the URL it could have used itself. Failures are reported in a sibling `delivery_failures` field — outside `items[]`, because an item is the protocol's own encoding and a field of ours inside it would corrupt bytes a signature covers — carrying the edge's own refusal token so an agent can distinguish a publisher's refusal from a custody fault.

### D4 — The proof-of-possession signer is app-side, pinned by shared vectors

The Go signing face for the agent-binding profile lives in `internal/httpsig` alongside the Web Bot Auth profile. Python already ships `sign_agent_binding` and TypeScript ships the verifier the edge runs; Go had neither, and the SDK's only Go artefact was an unexported test helper.

It does not route through the package's general signer. Two properties of the wire contract lie outside what the underlying library expresses: the parameter order is `keyid;alg;created;expires`, and `created` is injected rather than read from a clock. Both are fixed by the verifier the edge runs, so a second signature-base builder is the cost of speaking the contract. Byte parity is held by shared cross-language vectors rather than by review.

`@target-uri` is signed as the **verbatim URL string**, never a re-serialized `url.URL`: the edge rebuilds the base from the raw request line, so any normalization on the signing side yields a base it cannot reconstruct — and the failure surfaces as an undifferentiated 403 that says nothing about the URL having been the cause.

Upstreaming the signer into the SDK's Go helpers, so all three languages share one implementation, is desirable follow-up and not a prerequisite.

### D5 — `RAMP_ENFORCE_BINDING` returns, defaulting ON where capable

Restores ADR-013 D6.1. D6 is untouched: CloudFront-native cannot run the check and keeps the bearer posture.

Default ON because it is the standing decision, because the deployment documentation was never changed by the interim and still described default-on, and because the failure modes are asymmetric — enforcing fails loudly with a named reason, while not enforcing fails silently by serving a leaked URL to whoever holds it.

It is a variable rather than a second hardcode because deployments roll independently: an operator shipping an edge ahead of a registry that cannot yet present the key needs a way not to break every fetch in the interval. **Roll the registry first.** Opting out is explicit and is a downgrade to bearer security.

### D6 — Fetch posture: guarded, bounded, and non-following

- **SSRF-guarded transport.** A delivery URL is Exchange-supplied and offer-derived, not operator-configured — the same reasoning that already guards the usage-report leg.
- **Redirects refused.** The proof covers `@target-uri`, so replaying it at a new location fails the edge's own check, and re-signing per hop would hand a fresh proof of possession of the agent's key to whatever host the first hop named. This diverges from the SDK-agent fetch path, which follows redirects: a publisher edge that 302s works there and is refused here. Redirect support would need per-hop re-signing plus host anchoring, and is deferred.
- **The first hop is trusted; only later ones are not.** The bullet above refuses to present the agent's key to a host a *redirect* named, and the delivery URL's own host gets no equivalent check — the SSRF guard blocks internal address space, not an arbitrary public host. The distinction is deliberate: hop zero is named by the Exchange inside a response the caller's own transaction produced, whereas a redirect target is named by whoever answered. A compromised or malicious *registered* Exchange can therefore point the fetch at a host of its choosing and receive a valid, 30-second, URL-bound proof of possession — of a key whose public half is already published in the agent's WBA directory. That is accepted here rather than mitigated. Anchoring the delivery host against the offer's `identity.canonical_url` would close it and is the obvious follow-up; it is not free, because a publisher's CDN aliases need not match the canonical host.
- **Bodies are capped per item and per call, and an oversized body is refused rather than truncated.** Truncated content that looks whole is worse than a refusal — the agent has paid for it and cannot tell. The per-call cap exists because batch size is the caller's choice: bodies are buffered whole and base64-expanded into one JSON-RPC frame, so the per-item cap alone does not bound a call's memory.
- **A 2xx with an empty body is a delivered zero-length resource, not an error** — the edge's no-origin-mode path answers exactly that by design.
- **The key is resolved from the same source that signs offer acceptances.** This is the whole security argument in one line: the Exchange binds the URL to the acceptance key, so a key resolved any other way would be the wrong key. The signer additionally refuses to emit a proof whose `keyid` is not the thumbprint of the key in hand, so a custody layer that mispairs the two is caught at the source rather than three services away as a 403.

---

## Consequences

### Positive

- **ADR-013 D3 holds again**, and more widely than before the interim: a stolen URL is useless even to another registry user, because the registry signs each fetch as the calling agent and the edge rejects a mismatched `keyid`.
- **No protocol, Exchange, or edge change, and no agent-client change.** The narrowest of the five options that restores the property.
- **The custodial key never has to leave Vault's process boundary any more than it already did.** D1 adds a consumer of the existing signing seam, not a new export path.
- **ADR-017 D1's intent is honoured** — it anticipated the registry retrieving content for the agent, and that capability now exists. Not through the `ramp_fetch` tool it named: D2 folds the retrieval into `ramp_execute` and rejects a separately-invoked fetch outright, so the MCP surface is still the five `ramp_*` tools.
- **Delivery becomes observable in one place.** Fetch outcomes are reported per item with the edge's own refusal vocabulary, so a binding fault is diagnosable from the tool result rather than from three services' logs.

### Negative

- **The registry transits licensed content it does not license** — bandwidth, latency, a wider blast radius on compromise, and an operator-level question about handling licensed material.
- **The agent loses its own network path**: no client-side caching, no CDN affinity, no range requests.
- **Blob encoding costs about a third in wire size**, and content arrives base64 rather than as readable text. Emitting text for validated-UTF-8 text media types is a possible refinement; it was declined here because a partial rule is a second code path with a silent corruption mode at its edge.
- **A key rotation between signing the acceptance and fetching yields `keyid_mismatch`.** Eager fetching (D2) narrows the window to milliseconds but does not close it. Closing it means reusing the exact key already resolved for the acceptance, which changes the outbound port; deferred.
- **One knob sets two lifetimes.** `IDENTITY_MCP_SIGNATURE_TTL` now bounds both the RAMP call signature and the proof of possession, because the two are short-lived assertions about the same key. They are not the same risk, though: the PoP's covered set is only `@method` and `@target-uri`, so within its window the proof is replayable by anyone who observes the request. An operator who raises the value for a slow RAMP peer silently widens that replay window. Splitting them is a one-variable change if it ever matters.
- **Redirect behaviour diverges** from the SDK-agent path (D6).
- **A batch's memory cost is the caller's to set**, bounded but not small; the per-call cap makes it explicit rather than absent.

### Rejected alternatives

- **Agent-generated throwaway key attested by the registry (option A)** — the attestation is unverifiable by an offline edge without giving the edge a live trust path back to the registry (D1).
- **Registry as a remote signing service (option B)** — a signing oracle, plus a round trip per fetch (D1).
- **Leave enforcement off (option D)** — the interim being replaced; abandons D3 (D5).
- **Hardened bearer / one-time-use URLs (option E)** — needs shared edge state that ADR-013 already deferred, and still does not restore D3 (D1).
- **Handing the agent the custodial private key** — repeals ADR-017; rejected up front.
- **Registry-generated per-session keys delivered to the agent** — sends a private key over the wire for no benefit option A would not also give.
- **Lazy fetch behind an MCP resource template** — would need the bytes held between calls, and a re-fetch on read would record a second delivery in the edge log for a single purchase (D2).
- **The signed delivery URL as the embedded resource's `uri`** — MCP resource URIs are identifiers that clients de-duplicate, display and cite; a delivery URL is a short-lived credential carrying `sig`, `kid` and `agent_id`, and would be sprayed through every client's history and cache. The asset's canonical URL is used instead.

---

## References

- `docs/architecture/adr-013-agent-key-presentation-offline-binding.md` — the binding, its offline requirement, and the 2026-07-29 amendment restoring enforcement.
- `docs/architecture/adr-017-agent-identity-and-registration.md` — key custody and the RAMP adapter.
- `docs/architecture/adr-012-edge-delivery-log.md` — one delivery record per fetch, which D2 relies on.

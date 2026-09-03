# ADR-017 — Agent Identity & Registration (the Web Bot Auth Registry)

**Status:** Proposed (2026-06-17)
**Realisation (2026-07-29):** D1 has shipped. The Go registry service and its MCP adapter live in `src/identity`, with all five `ramp_*` tools (`ramp_register`, `ramp_status`, `ramp_discover`, `ramp_execute`, `ramp_report`) under `src/identity/internal/mcp/`. The status above is deliberately unchanged: the decisions below have not been re-reviewed since they were proposed, so read them as the design the shipped code follows, not as a ratified contract.
**Adjustments (2026-08-26):** D2 and D7 carry dated **Adjustment** notes directly beneath them. Decision text in this ADR is never edited in place — it records what was decided, and stays as decided. An adjustment is additive: it names the decision it qualifies, says what has changed since and what still stands, and leaves the original paragraph intact above it. Read an adjusted decision together with its note; a decision with no note is unqualified.
**Builds on:** ADR-009 (identity boundary), ADR-013 (agent-key presentation), ADR-014 (Universal Licensing Core), ADR-015 (edge free-index fast path), ADR-016 (edge-resolved capability access). Realises the WBA identity direction, and reframes the agent-registration and publisher-well-known models that preceded it — coordinate with their owners before re-statusing.

---

## Context

Agents that will **not adopt an SDK** still need a cryptographic identity and a way to talk to the Exchange/Broker. Today that is a thin Python `ramp_fetch` shim — an adoption crutch, not production software, and the wrong tool to hold private keys. Separately, **publishers** need to authorize an Exchange to sell their content. Identity is decided to use the **Web Bot Auth (WBA)** standard (Ed25519 + RFC 9421 HTTP Message Signatures + a JWK directory at a well-known path) so a RAMP-provisioned party is verifiable anywhere WBA is (Cloudflare edge, AWS AgentCore, any WBA origin).

The load-bearing requirement: a **licensing agreement needs a known, bindable licensee.** WBA proves only *key-possession + a domain* — that is **not** a licensee. So identifying the licensee is the core job, and it is required for essentially everyone. There are zero users and the proto is in flux, so reopening the wire contract is acceptable.

## Decision

### D1 — A Go "Web Bot Auth Registry" service replaces the FastMCP shim
A single Go binary, two layers: a **RAMP-agnostic WBA Identity Provider core** (keygen + custody, mint a subdomain, host the well-known JWKS directory + a Signature Agent Card, RFC-9421 request signing, developer sign-up, the directory) and a **thin RAMP adapter** (the MCP tools `register` / `ramp_fetch` / `status`). Go because the codebase is Go (reuse `internal/httpsig`, `ramphttpsig`, `rampwellknown`), crypto is stdlib-grade, a single static binary is the minimal attack surface for a key-custody service, and the Go MCP SDKs are production. The core is independently shippable ("spin up Web Bot Auth for anyone"); RAMP is its first consumer.

**Scope of "RAMP-agnostic".** The rule is about the documents a generic Web Bot Auth verifier reads: the key directory and the Signature Agent Card are built to the standards' shape, never marshalled from RAMP's protobuf, so any WBA verifier on the open internet can consume them. It is not a rule that no RAMP-shaped byte may leave the service. Per D2 the registry also serves each agent's RAMP commercial overlay, which is RAMP's own document with no audience outside RAMP and is built directly from the protocol module.

### D2 — Two identity surfaces; the registry is agent-side
- **Agents → the hosted registry.** On registration the agent is issued **`<agent-id>.rampmcp.org`**, and the registry **hosts its whole `/.well-known/`** — the WBA `http-message-signatures-directory`, the Signature Agent Card, the key-revocation list, and the RAMP commercial overlay (`ramp.json`) — and optionally a user-facing card page.
- **Publishers → self-hosted split well-known**: the pure WBA file (identity keys, per the WBA split) **plus** the RAMP-specific overlay (`ramp.json`: authorized exchanges, commercial graph). Publishers own a domain, so self-serving is trivial. **The publisher-hosted model is distinct and needed**: what the registry takes over is hosting for agents that have no domain of their own, not the publisher's authority to declare who may sell its content.

**The agent overlay is a role marker.** Every RAMP participant serves an overlay, so an agent hosted here serves one too, but an agent's carries only `ver`, `role: ROLE_AGENT`, and `domain`. The publisher-only fields (authorized exchanges, catalog contributors) and the exchange-only capability fields do not apply to it, and identity keys are in none of them — they are in the WBA directory, referenced by RFC 7638 thumbprint. A verifier resolves that directory from the covered `Signature-Agent` header, never from the overlay, so the agent overlay is a statement of role, never an input to authentication.

**"Registered" means an account row exists.** The overlay is served for a subdomain that the developer-account table claims, and 404s otherwise. That row is the authoritative record: sign-up reserves it BEFORE minting the Vault key and writing the card, across three backends with no transaction spanning them, and is designed to be replayed after a crash between those steps. So the agent's other published documents are not a sound test of registration in either direction — a reserved account whose key never landed has none of them, and an orphaned key has no account behind it. Whether the developer has finished the mandatory registration form is deliberately not part of the test: the form gates what the agent may transact, while the account row is what claims the subdomain as an identity. An agent mid-onboarding therefore serves its role marker while its WBA directory still 404s.

**Adjustment (2026-08-26) — D2.** The registration form the paragraph above depends on no longer exists. The registry served a mandatory form during sign-up and kept a completion flag on the developer account; the route, the template, the validation and the column are all removed, and nothing in this service now gates what an agent may transact on a per-developer flag. The rest of the paragraph stands unchanged: the account row is still the authoritative record, still reserved before the Vault key and the card, and an agent mid-onboarding still serves its role marker while its WBA directory 404s. In place of that clause: there is no second gate left to ask about, because sign-up provisions the identity and nothing else. Whether the agent has registered as a licensee is a per-Exchange question (D6, and the adjustment under D7) that this service does not track.

### D3 — Identity is the key thumbprint, proven per-request
A party's identity is its Ed25519 key thumbprint (RFC 7638), proven by the per-request RFC 9421 signature (holder-of-key, per ADR-013/016). `billing_ref` is per-exchange and resolved from the verified thumbprint.

### D4 — Licensee identification is mandatory; registration is the norm
Because a licensing deal needs a bindable counterparty, **every party must be identified as a licensee.** WBA + a domain is not enough. Registration is the default path; the only carve-outs are the two narrow cases in D5. **Free access is not anonymous access** — a free crawler still needs an identified licensee unless it is whitelisted.

### D5 — Three ways a licensee is identified
- **(a) Whitelisted crawler** — a *handful* of pre-identified operators (Google, Perplexity, …). WBA signature only, no registration; the identity is the whitelist entry. **The whitelist is curated by the publisher** (not the Exchange operator) via the **Publisher interface of the Exchange** (alongside content ingestion), and propagates to the **Edge KV** store. The response carries a **license reference (RSL terms)** — by crawling you accept the terms (use = acceptance).
- **(b) Publisher-issued biscuit, edge-resolved** — the publisher pre-authorizes a specific agent **out-of-band** with a signed biscuit (e.g. free *unmetered* access for AI answers). The agent presents the biscuit; the edge **(or the publisher's own server — the edge is not required)** verifies signature + scope and serves directly. The agent never touches the Exchange except `ReportUsage`. **No offers, no registration** — the licensee was identified by the publisher when it issued the biscuit. **The binding, reporting obligations, and reconciliation for this path are defined in ADR-016** — this ADR only consumes them.
- **(c) Registered licensee** — everyone else. Must register (D6) to become an identified, bindable licensee — **including for free access.**

### D6 — Explicit `Register`; the Exchange trusts the signature for identity and derives the binding
Registered licensees register via an explicit `Register` RPC. The security binding `billing_ref ↔ verified thumbprint` is **derived server-side from the signature, never read from the caller payload.** The Exchange does not inspect or validate the business payload (the SoR's concern) and never lets the caller name who is billed or which tenant — closing the caller-controlled-identifier bug class without business rules in the Exchange. Registration responses are signed (RFC 9421 both ways).

### D7 — Registration metadata: specific Agent-Card fields + the licensing-deal fields
**From the agent's Signature Agent Card → the SoR (exact fields, no `keys`):**

| Card field | SoR field | Notes |
|---|---|---|
| `client_name` | `display_name` | |
| `client_uri` | `info_uri` | |
| `contacts` | `contacts` | e.g. `mailto:` |
| `purpose` | `declared_use` | **translated** to an RSL function token (D9) |

Keys are **not** stored in the SoR (they live in the registry; D10). The card may be **non-conformant or missing "required" fields** — nothing stops a publisher serving JSON with a field absent — so every field is treated as possibly-absent. The **`ramp-registration-v1` profile** documents exactly which fields RAMP consumes, their SoR mapping, and the card→RSL translation.

**Collected at registration (not on the card; required for every registered licensee, because a licensing deal needs them):** **legal entity, address, jurisdiction** (and common-sense minimum — deliberately not exhaustive).

**Adjustment (2026-08-26) — D7.** The requirement stands, and so do D4 and D5(c) that rest on it: every registered licensee still supplies these fields. What changed is where they are collected and who holds them. The identity registry used to collect legal entity, address and jurisdiction through a mandatory web form of its own and store them on the developer account, then forward them as `registration_data` when an agent opened an Exchange account. The form, its route and template, and the columns behind it are removed. The developer account now carries only what identity provisioning needs — the OIDC issuer and subject, the email, and the minted subdomain. They are supplied per Exchange now, in the `ramp_register` tool call the agent makes, and the Exchange's system of record holds them: `sor.agent_accounts` has typed columns for legal entity, jurisdiction and address, and copies any key it does not recognize into its `extra` JSONB. One form in the registry could only ever encode one Exchange's requirements, and each Exchange decides its own.

### D8 — Intended-use is governed per-request by signed `X-Intended-Use`, not the mutable card
The card is self-asserted and mutable, so it is **never a gate.** What is enforced is the **signed `X-Intended-Use`** at fetch time (ADR-015), which cannot drift between registration and fetch; the edge/Exchange matches it against the term's restrictions. The card's `purpose` is a descriptive hint only.

### D9 — Vocabulary = RSL; alias to AIPREF/WBA; translate the card
RAMP's three restriction kinds **are** the RSL vocabularies, already in the proto-native vocab — expandable, but **invent no new value for an existing concept**:
- `RESTRICTION_KIND_FUNCTION` = RSL `usage`: `all`, `ai-all`, `ai-train`, `ai-input`, `ai-index`, `search`.
- `RESTRICTION_KIND_USER_TYPE` = RSL `user`: `commercial`, `non-commercial`, `education`, `government`, `personal`.
- `RESTRICTION_KIND_GEOGRAPHY` = RSL `geo`: ISO 3166-1 alpha-2 (+ specials `*`, `EU`, `EEA`).

`X-Intended-Use` carries an RSL function token. **Translate** the WBA card's free-text `purpose` (e.g. `tdm`) and any AIPREF `Content-Usage` term into the RSL token (`train-ai`→`ai-train`, etc.) — a thin alias, not a new vocabulary. Follow-up cleanup: reconcile any non-RSL function token already used (e.g. `crawl`, which in RSL is a *payment/access* type, not a *usage*). See appendix.

### D10 — Key-free SoR via a `SoRAdapter` (webhook-capable)
The SoR is accessed through a **`SoRAdapter`** — a pluggable interface parallel to the existing `BillingAdapter`, which the operator backs with their store (default: a no-code form builder that doubles as the operator console). It **supports webhooks** — e.g. the SoR pushing an **activation-status flip** the Exchange mirrors. Interface: `onRegister(billing_ref, registration_data)`, `isActive(billing_ref)`, `getLicenseeProfile(billing_ref)`; admin `setAccountActive(billing_ref, active)`. The SoR holds **no keys**; key lifecycle (gen/rotate/revoke) lives in the registry.

### D11 — Key custody via an abstract security-store adapter (Vault or local, swappable)
The registry custodies agent private keys through an **abstract security-store interface (a `KeyStore` adapter)**. The reference deployment backs it with **HashiCorp Vault**. A **local backing is permitted as a swappable interim** (faster to ship) provided it implements the same interface, so moving to Vault is an adapter swap, not an architecture change. **MCP-user key custody is independent of any single tenant's preference**; publisher/exchange/broker custody is the operator's choice. The custodial risk is **decoupled from the RAMP protocol** (RAMP only verifies signatures), **intrinsic** to the SDK-less-agent surface, and a managed operational cost (as for any registry) — not a RAMP design flaw. Keys are exportable (a user can graduate to self-custody).

## Consequences

**Positive.** Standards-aligned and federatable (Signature Agent Cards, IAB Agent Registry listing); replaces a throwaway shim with production software; a potential standalone product; the Exchange stays a thin binding-validator; identity / governance / vocabulary each reuse an existing standard (WBA / signed `X-Intended-Use` / RSL); custody and SoR are both adapters (swap without architecture change).

**Negative / risks.** A custody adapter + per-subdomain DNS/TLS for `*.rampmcp.org` are real surfaces to build/operate. Depends on **WBA being an IETF draft** (the directory path may still shift). Both-ways response signing is **additive — a feature, not a wire-contract change** — so it is not a blocking dependency. The path-(b) flow depends on ADR-016 (which owns its mechanism). Reopens the proto (acceptable: zero users).

**Process.** The agent-registration work is in review and the deployment-side networking is owned by colleagues; the reframe is the architect's call but must be communicated to the implementers before they build the old shape.

## Open questions
1. The exact `ramp-registration-v1` commercial fields beyond legal entity / address / jurisdiction.
2. Custody hardening cadence — when the local `KeyStore` interim must move to Vault/HSM.

## Appendix — vocabulary harmonization (reference, not new vocab)

| Concept | RSL / RAMP (canonical) | AIPREF `Content-Usage` | WBA card `purpose` |
|---|---|---|---|
| Train / fine-tune AI | `ai-train` | `train-ai` | `tdm` (≈) |
| Input / RAG / grounding | `ai-input` | use/input (RAG) | `tdm`/`ai-input` (≈) |
| AI internal index | `ai-index` | (index) | — |
| Search index + excerpts | `search` | `search` | `search` (≈) |
| Any AI use | `ai-all` | — | — |
| Any automated use | `all` | — | — |

Sources: RSL 1.0 §3.4.1.1 (rslstandard.org/rsl); IETF AIPREF vocab (draft-ietf-aipref-vocab); WBA registry / Signature Agent Card (draft-meunier-webbotauth-registry).

# ADR-004 — RAMP Protocol Layers (biscuit-authoritative inner; HTTP+JWT+RFC 9421 outer shim)

**Status:** Accepted (2026-04-23)
**Refines:** `docs/architecture/adr-001-three-layer-auth.md` — ADR-001 framed the three layers as coequal and load-bearing; this ADR pins which layer is authoritative for authorization and which layers are deployment conveniences.
**Companion documents:**
- `docs/architecture/adr-002-entitlement-biscuit-model.md` — the single biscuit whose chain constitutes the inner layer.
- `docs/architecture/adr-003-key-rotation-revocation.md` — rotation mechanics at the biscuit layer.
- `docs/architecture/adr-005-biscuit-transport-canonical-binding.md` (forthcoming) — canonical-form request-hash attenuation that makes the inner layer transport-independent.
- `docs/architecture/adr-006-broker-intermediation.md` (forthcoming) — `authorized_intermediaries` mechanism that keeps hop visibility enforceable at the inner layer.

---

## Context

ADR-001 established that every authenticated request carries three independent cryptographic assertions:

1. RFC 9421 HTTP Message Signature
2. JWT issued by an OIDC IdP (Zitadel in our stack; Okta/Azure AD/Keycloak/Ping in customer stacks)
3. Entitlement Biscuit (resource-owner-signed authority block + mandatory per-request buyer attenuation)

ADR-001 treated the three layers as coequal and argued against collapsing any of them. That framing served the primary goal of ADR-001 — preventing "one-layer-does-everything" drift — but it left an ambiguity the design keeps colliding with: **which layer is the protocol, and which layers are accommodations?**

A 2026-04-23 review surfaced the concrete tension:

- A `RAMPRequest` crossing a non-HTTP transport (queue, archive, MCP tool-to-tool, A2A) has no HTTP headers and no RFC 9421 signature. Is the request still authorizable? If yes, RFC 9421 is not load-bearing. If no, RAMP is not transport-independent — it is RAMP-over-HTTP.
- Enterprise deployment value of JWT (SIEM, API-gateway integration, library availability) is real. But none of that value is authorization value — Exchange's authz verdict could be computed from biscuit facts alone. Gate D's `jwt.org == authority.subscriber_org` check is a cross-check against a JWT claim whose source of truth is already in the biscuit's `subscriber_org` fact.
- A biscuit-only profile — agent keypair is identity, no IdP, no OIDC, everything cryptographically self-describing inside the biscuit chain — is a viable protocol for non-enterprise deployments (individual buyers, MCP wallets, developer tooling). ADR-001's framing implicitly rules this out by requiring JWT.

The review concluded that the three layers are *not* equivalent. One of them is the protocol; the other two are production deployment shims. Making this explicit in an ADR is the move that lets the design stop oscillating between "ADR-001 says three layers" and "the protocol demands only one."

---

## Decision

RAMP has **two layers**, not three:

### Inner layer — the protocol

The inner layer is biscuit-only. It comprises:

- **Entitlement biscuit** (per ADR-002): resource-owner-signed authority block + mandatory buyer-signed per-request attenuation. Carries identity facts (`subscriber_org`, `agent_id`, `sub`) alongside authorization facts (`grants`, `contract_id`, `valid_from`/`valid_until`) and transport facts (`buyer_keys_url`, `renewal_url`).
- **Canonical-form request hash** (per ADR-005, forthcoming): per-request attenuation carries `request_hash(sha256(canonical_body))` fact. Gate F asserts the received body canonicalizes to this hash. Binds biscuit to request body without depending on transport headers.
- **Biscuit chain verification** (biscuit-go / biscuit-python libraries): the Datalog authorizer evaluates facts and checks, producing the authorization verdict.
- **Key rotation and revocation** (per ADR-003): key material is discovered via URLs embedded in biscuit facts (`buyer_keys_url`, `renewal_url`, JWKS-metadata `revocation_url`), not via external directories or IdP APIs.
- **Gates A–F** at Exchange: operate on biscuit facts. The verdict is a function of the biscuit chain and the canonical request form, nothing else.

The inner layer is **transport-independent**. The biscuit is opaque framing regardless of whether it rides an HTTP header (Tier 1), `RAMPRequest` envelope (Tier 2), or sub-message field (Tier 3). It is **IdP-independent**. It is **HTTP-independent**. A RAMP request expressed as a proto message on disk is fully verifiable by anyone holding the resource-owner pubkey and the buyer pubkey.

### Outer layer — enterprise deployment shim

The outer layer comprises:

- **`Authorization: Bearer <JWT>`** issued by an OIDC IdP (Zitadel in our stack, customer-chosen IdP in production).
- **RFC 9421 HTTP Message Signature** covering method, URI, content-digest, authorization header, and (when present) `x-ramp-entitlement-biscuit` header.
- **JWKS-over-HTTPS** discovery for buyer/resource-owner pubkeys and revocation lists (the well-known convention documented in the proto top comment).
- **Gate D (`jwt.org == authority.subscriber_org`)** and the Gate A `sub(jwt.sub)` cross-check: defense-in-depth checks that compare JWT claims to facts already present in the biscuit. Redundant to the inner layer's correctness; retained because redundant checks catch integration bugs that a pure-biscuit deployment wouldn't notice (wrong JWT bound to right biscuit, right JWT bound to wrong biscuit).

The outer layer exists for four reasons, in priority order:

1. **Enterprise SIEM / API-gateway / service-mesh integration.** Every compliance-heavy buyer's audit and observability stack derives principal, tenant, and correlation tags from `Authorization: Bearer`. Stripping the JWT forces customers to rebuild that infrastructure around a non-standard header — a non-starter for the first wave of adopters.
2. **OIDC as integration contract with corporate IdPs.** Okta, Azure AD, Keycloak, Ping, Google Workspace all ship OIDC first-class. The outer layer is the handshake that binds corporate user identity to the RAMP request without requiring each customer to author a token-exchange shim.
3. **Library availability.** JWT libraries are pre-approved in every enterprise language stack. Biscuit libraries are not; "add a Rust crypto dependency" is a multi-week compliance review in regulated environments. The outer layer lets agents sign with library code they already have deployed.
4. **Transport observability.** RFC 9421 gives network middleboxes something to inspect, log, and rate-limit without parsing proto. Visibility at the HTTP layer is load-bearing for deployment, even when it is not load-bearing for authz.

**The outer layer does not produce authorization verdicts.** Exchange's authz decision is the biscuit chain's verdict, qualified only by Gate D and Gate A cross-checks — which can be disabled in a biscuit-only deployment without weakening the authz decision, because the inner layer already carries the facts those cross-checks compare against.

### Rule for future design

Any new feature proposed for the outer layer MUST NOT make the inner layer less complete. If a capability moves out of the biscuit and into JWT or RFC 9421, the protocol loses transport-independence and the biscuit-only profile stops being viable. The direction of travel is the opposite: features currently implicit in the outer layer (e.g. body-bind via RFC 9421 `content-digest` covering `x-ramp-entitlement-biscuit`) migrate inward as explicit biscuit facts (ADR-005's `request_hash` fact).

---

## Biscuit-only profile

Documented as a supported future deployment mode, not a near-term deliverable. The inner layer already supports it.

In a biscuit-only deployment:

- Identity is a keypair. Agent-identity is `agent_pubkey(hex)` as a biscuit fact; there is no `sub`, no `org`, no IdP.
- Buyer delegation is a biscuit attenuation appending the agent pubkey to the authority block's permitted-agent set. No SSO query.
- Resource-owner and buyer pubkeys are exchanged at contract signing via whatever out-of-band channel humans already use for contract keys.
- Transport is opaque. Requests ride any carrier that can transport bytes.
- Revocation is still biscuit-signed list at the URL pinned in the authority block's `revocation_url` fact. Same mechanism, no JWKS-over-HTTPS dependency.
- Gate D and the Gate A `sub(jwt.sub)` cross-check are disabled. Gates A (biscuit side only), B (buyer key freshness), C (revocation), E (authority TTL), and F (canonical-form binding) still run and are sufficient.

The biscuit-only profile is the purely-transport-independent version of RAMP, useful for individual buyers, MCP wallets, developer tooling, non-enterprise marketplaces, and any deployment where "add OIDC" is a larger burden than "add a biscuit library." It is not a fork of the protocol — it is ADR-004's inner layer standing alone.

---

## Consequences

### Positive

- **Clarity of load-bearingness.** "The biscuit is the protocol; JWT + RFC 9421 are production shims" answers questions the design kept relitigating: *can RAMP travel over non-HTTP?* (yes), *is JWT required?* (only for enterprise deployment), *does a broken JWKS endpoint block authz?* (only if the broken endpoint serves biscuit keys; a broken IdP JWKS does not), *can Gate D be disabled?* (yes, in biscuit-only profile).
- **Enables ADR-005's canonical-form binding.** If RFC 9421 were load-bearing, canonical-form request-hash would be redundant ceremony. Because the outer layer is a shim, the canonical-form binding at the biscuit layer becomes the authoritative body-bind — RFC 9421 becomes transport-integrity only.
- **Enables ADR-006's broker intermediation model.** Biscuit attenuation appending is the mechanism; an outer-layer-based broker transparency scheme would have to reinvent the chain-of-hops visibility that the biscuit already provides.
- **Future-proofs non-HTTP transports.** A2A, MCP tool-to-tool, queues, archives, and dispute-resolution replay all become first-class because they inherit the inner layer's transport-independence.

### Negative

- **Drift risk between inner and outer.** If developers consistently implement new features at the outer layer (because HTTP is easier), the inner layer will fall behind and the biscuit-only profile will stop working. Mitigation: the "rule for future design" above; reviewers enforce that any new authz-adjacent feature is expressible in biscuit facts first.
- **Gate D and Gate A cross-check ambiguity.** These gates are defense-in-depth but live in the Exchange code path today. Someone reading the code and not this ADR could believe they are load-bearing. Mitigation: code-level comments on Gate D and Gate A cross-check pointing to this ADR.
- **Double-signing cost.** In HTTP deployments the biscuit is covered by RFC 9421 AND carries its own canonical-form hash (ADR-005). Small wire-level overhead; real operational cost is ~zero. Kept because RFC 9421 is what enterprise middleboxes observe.

---

## Rejected alternatives

### Keep ADR-001's three-coequal framing

Rejected. The coequal framing is accurate as deployment observation but imprecise as protocol definition. "All three layers are always present" is true in enterprise deployment; it is not true of the protocol.

### Eliminate the outer layer (biscuit-only as default)

Rejected for near-term. Enterprise adoption requires OIDC + SIEM + API-gateway integration; the outer layer is the cost of being deployable into compliance-heavy environments. Documenting biscuit-only as a future deployment mode preserves the option without shipping it as default.

### Keep JWT, drop RFC 9421

Rejected. RFC 9421 is the mechanism that ties the JWT to the specific request, closes the replay window beyond what the JWT's `exp` provides, and gives enterprise middleboxes request-level observability. JWT alone would open JWT-replay surface.

### Keep RFC 9421, drop JWT

Rejected. The enterprise integration value (§reasons 1–3 above) is in the JWT, not in RFC 9421.

---

## Non-goals

- This ADR does not change the wire format. All proto fields, HTTP headers, and gate logic stay as defined in ADR-002, ADR-003, ADR-005.
- This ADR does not remove any gate. Gates D and A cross-checks are retained in the default (enterprise) deployment profile.
- This ADR does not commit to shipping the biscuit-only profile. It documents the profile as a consequence of the two-layer framing, not a near-term deliverable.

---

## References

- ADR-001 (three-layer auth) — status updated to "Refined by ADR-004."
- ADR-002 (entitlement biscuit model) — source-of-truth for the inner layer.
- ADR-003 (key rotation and revocation) — inner-layer mechanics.
- ADR-005 (biscuit transport carriage + canonical-form binding) — forthcoming; makes the inner layer fully transport-independent.
- ADR-006 (broker intermediation + transparency chain) — forthcoming; extends the inner layer to cover multi-hop authorization.

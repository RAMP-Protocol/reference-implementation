# ADR-001: Three-Layer Auth Model (RFC 9421 + JWT + Biscuit)

**Status:** Refined by ADR-004 (2026-04-23). The three-layer framing is correct as an observation of enterprise deployment shape; ADR-004 refines the framing to pin which layer is authoritative for authorization (inner: biscuit) and which layers are deployment shims (outer: JWT + RFC 9421). See `docs/architecture/adr-004-protocol-layers.md`.
**Originally accepted:** 2026-04-21.
**Supersedes:** — (new record; supersedes the unpublished "unwrap-to-biscuit at MCP shim" proposal discussed and rejected on 2026-04-21)
**See also:**
- `docs/architecture/adr-002-entitlement-biscuit-model.md` — single resource-owner-signed entitlement biscuit + mandatory per-request buyer attenuation; expands Layer 3 below.
- `docs/architecture/adr-003-key-rotation-revocation.md` — rotation and revocation mechanics for all four key hierarchies referenced in this ADR.

---

## Context

Every authenticated request arriving at Broker or Exchange carries three independent cryptographic assertions:

1. **RFC 9421 HTTP Message Signature** (request-level integrity, non-replay, keyid → agent pubkey).
2. **JWT** issued by an OIDC IdP (Zitadel in our stack; Okta / Azure AD / Keycloak / Ping in customer stacks). Provides `sub` / `iss` / `aud` / `exp` — the "principal envelope".
3. **Biscuit token**: a single entitlement biscuit issued by the resource owner at contract-signing time, with mandatory per-request attenuation signed by the buyer-side delegation key (see ADR-002).

Reviewers asked during the 2026-04-21 session whether the JWT layer could be eliminated at the MCP-shim boundary by unwrapping `jwt.biscuit` claim into a bare Biscuit before the request ever leaves the agent host. The argument was that Exchange would then only see one authn input (Biscuit), simplifying the authz surface and removing the "JWT+Biscuit monster" from server code.

The proposal was rejected on two grounds:

1. **Enterprise SIEM / API-gateway / service-mesh integration assumes JWT.** Every enterprise deployment we have to interoperate with already derives principal, subject, and tenant tags from the `Authorization: Bearer <jwt>` envelope — for audit logs, rate limiting, anomaly detection, and cross-service correlation. Stripping the JWT at the MCP shim would force customers to rebuild that observability stack around a non-standard header (`X-RAMP-Identity-Biscuit`). That is not a tradeoff a compliance-heavy buyer will accept.
2. **OIDC / JWT is the integration contract every corporate IdP exposes.** Okta, Azure AD, Keycloak, Ping, Google Workspace all ship OIDC as the first-class integration. Dropping the JWT layer would mean every customer rolls a custom token-exchange shim between their IdP and RAMP. "Biscuit only" is a viable protocol for the authz core but a non-starter as the integration contract.

The three layers therefore coexist. This ADR pins down what each layer is for, and — critically — what each layer is **not** for, so the design cannot drift back into the "one layer does everything" attractor under future refactors.

---

## Decision

The three cryptographic layers serve three disjoint purposes and MUST NOT be composed or substituted.

### Layer 1 — RFC 9421 HTTP Message Signature

- **What it proves:** the HTTP request itself is authentic, body-intact, and not replayed within the signature window.
- **Verifier input:** the `Signature-Input` / `Signature` headers; `keyid` resolves to the calling agent's or MCP-shim's registered Ed25519 pubkey.
- **Used for:** request-level integrity; non-repudiation for compliance audit; interoperability with enterprise signature-auditing tools (the correctness win that justifies the layer existing at all).
- **NOT used for:** identity-to-authz translation. A valid RFC 9421 signature proves "this request came from an agent with key X"; it does not prove "agent with key X is authorized to fetch Y".

### Layer 2 — JWT (OIDC access token)

- **What it proves:** a principal authenticated at the IdP and consented to the OAuth grant. Carries `sub` / `iss` / `aud` / `exp` / `org` / `email` / `idp_alias` directly as JWT claims. Per ADR-002 identity facts are native JWT claims — no separate identity artifact is minted at the IdP boundary.
- **Verifier input:** IdP JWKS (RS256).
- **Used for:**
  - SIEM and audit-log correlation across the enterprise perimeter.
  - API-gateway and service-mesh policy (rate limits, quota tagging, tenant dispatch).
  - Distinguishing human-backed principals from service identities at the telemetry layer.
  - Source of `user(jwt.sub)` and `org(jwt.org)` facts that Exchange injects into the Datalog world at authz time (see ADR-002 §E).
- **Authz contract:** JWT claims are admissible as identity facts (`user`, `org`) inside the Datalog world only via the well-defined injection point named by ADR-002. Free-form reads of `jwt.scope`, `jwt.email`, etc. inside `src/exchange/internal/service/` or `src/exchange/internal/transport/` to drive allow/deny remain forbidden:
  - Such reads require an explicit reviewer sign-off referencing this ADR.
  - URL-signing subject is derived from `jwt.sub` (the identity envelope) — the JWT is the sole carrier of principal identity at the authz boundary.
  - The JWT is end-user scoped. It MUST NOT be used as a service-to-service credential; service-to-service identity uses RFC 9421 keyid + registered pubkey.

### Layer 3 — Biscuit (single entitlement biscuit with mandatory attenuation)

- **What it proves:** what a principal is authorized to do, as a cryptographically-verifiable Datalog fact set. Updated by ADR-002 to a single biscuit on the wire:
  - **Authority block** (issued by the resource owner at contract-signing time): what the buyer org is entitled to — `resource_owner(...)`, `subscriber_org(...)`, `buyer_delegation_pubkey(...)`, `buyer_keys_url(...)`, `grants(...)`, `contract_id(...)`, `valid_from(...)`, `valid_until(...)`.
  - **Attenuation block** (signed by the buyer's delegation key, MANDATORY per request): narrows the entitlement to the specific user, operation, resource prefix, and time window of this request, with a ≤10-minute TTL and a `sub(jwt.sub)` fact binding it to the JWT principal.
- **Used for:** the primary input to Exchange authz decisions, layered with five service-level policy gates (see ADR-002 §E). Identity facts (`user`, `org`) are derived from the JWT and injected into the Datalog world at authz time — the JWT carries the identity envelope, the biscuit carries authorization.
- **Chosen for:** native attenuation (can only restrict, never expand — enforced by biscuit-lib); offline verification (no IdP round-trip at the authz boundary); resource-owner-signed scopes (the resource owner is the ground-truth authority on entitlements, not the IdP).

### Summary table

| Layer | Proves | Verifier reads | Drives authz? |
|---|---|---|---|
| RFC 9421 | request integrity + agent-key possession | `Signature-Input` header, `keyid` | No |
| JWT | principal authenticated at IdP | IdP JWKS (RS256) | **No — hard rule** |
| Biscuit | authorization facts (single entitlement biscuit, resource-owner-signed authority + mandatory per-request buyer-signed attenuation; see [ADR-002](adr-002-entitlement-biscuit-model.md)) | resource-owner entitlement-biscuit root + buyer delegation pubkey (Ed25519) | **Yes — primary input, with JWT-derived `user`/`org` facts injected** |

---

## Consequences

### Positive

- **Enterprise SIEM / gateway integration preserved.** Customers keep their existing JWT-based audit and rate-limit pipelines; RAMP does not ask them to re-tool observability.
- **Exchange authz is simplified, not complicated.** Although three layers reach Exchange, only one (Biscuit) feeds the authorizer. The service-layer code path has a single, well-typed authz input; the other two layers are verified at the transport boundary and discarded from the authz decision.
- **Attenuation stays intact.** Because authz is Biscuit-only, buyer-side attenuation is the single lever for narrowing delegation. JWT scopes cannot accidentally override or broaden the biscuit chain.
- **URL-signing subject is stable across IdP changes.** Swapping Zitadel for Okta changes the JWT `sub` format but not the biscuit's `user(...)` fact, so downstream artifacts (signed URLs, audit ledger) remain schema-stable.
- **Failure modes are isolated.** A bug in JWT parsing at the SIEM layer cannot open an authz hole at Exchange; a bug in biscuit verification cannot bypass request-integrity checks.

### Negative / costs accepted

- **Three independent verifications per request.** Broker verifies all three; Exchange re-verifies all three (does not trust Broker's assertions). This is an intentional CPU cost for trust-boundary hygiene.
- **Multiple key hierarchies.** Four distinct hierarchies (agent Ed25519, IdP RS256, entitlement-biscuit Ed25519 per resource owner, buyer delegation Ed25519). Runbook complexity is real but all key sets are discoverable via `/.well-known/*` endpoints (or, for buyer delegation keys, the opaque `buyer_keys_url` recorded in the authority block) with documented rotation procedures (see ADR-003).
- **A lint gate is required and load-bearing.** Without enforcement, a reviewer can drift Exchange service code into reading `jwt.sub` because "it's easier". The enforcement (see below) is not optional; it is the mechanism that makes this ADR durable.

---

## Alternatives considered

### (a) Unwrap JWT → Biscuit at the MCP-shim boundary (rejected, 2026-04-21)

**Proposal:** MCP shim receives the JWT from Zitadel, extracts the `biscuit` claim, and forwards *only* the Biscuit to Broker/Exchange. The JWT never crosses the MCP-shim → Broker hop.

**Rejected because:**

1. **SIEM and API-gateway integration breaks.** Every enterprise observability pipeline at the customer perimeter expects `Authorization: Bearer <jwt>`. Removing the JWT from outbound requests forces customers to build a parallel telemetry path for RAMP traffic — a non-starter for compliance-heavy buyers.
2. **OIDC is the corporate IdP contract.** Okta / Azure AD / Keycloak / Ping / Google Workspace all expose OIDC first. The JWT is the integration surface; dropping it requires each customer to write a bespoke token-exchange shim. The adoption tax is not worth the (modest) server-side simplification.

### (b) JWT-only (rejected)

**Proposal:** use JWT scopes (`"scope": "examplenews:read"`) for authz; drop Biscuit entirely.

**Rejected because:**

- **No attenuation semantics.** JWT scopes are flat strings; there is no cryptographic guarantee that a downstream party cannot forge a broader scope. Biscuit attenuation is proven by the biscuit-lib chain verification.
- **No offline verification.** JWT scope interpretation in a multi-resource-owner setting requires the IdP to know every resource owner's entitlement model, or requires token-introspection round-trips at the authz boundary. Biscuit is verified offline against the per-resource-owner entitlement-biscuit signing pubkey.
- **OIDC does not see the entitlement issuer.** Resource owners issue entitlements at contract-signing time, well outside the IdP's knowledge. Biscuit lets resource owners sign grants directly without coupling to the IdP.

### (c) Biscuit-only (rejected)

**Proposal:** drop the JWT layer entirely. Agents authenticate to RAMP with a Biscuit from the start; no OIDC.

**Rejected because:**

- **No enterprise IdP integration surface.** Corporate identity lives in Okta / Azure AD / Keycloak / Ping / Google Workspace, all of which speak OIDC. A Biscuit-only stack requires every customer to build a custom IdP-to-Biscuit exchange, which is the integration tax that killed option (a) on a larger scale.
- **No SIEM correlation.** Enterprise audit tooling keys off JWT `sub` / `iss`. Biscuit fact sets are opaque to standard SIEM parsers.
- **Violates ADR-057 (paused).** ADR-057 commits RAMP to OAuth 2.0 as the enterprise adoption bridge. Biscuit-only contradicts the paused methodology's core adoption thesis.

---

## Enforcement

This ADR is durable only if the "JWT claims MUST NOT drive authz" rule is mechanically enforced. Two layers of enforcement:

### Code review checklist (immediate)

Any PR that touches `src/exchange/internal/service/` or `src/exchange/internal/transport/` (the Connect-Go handler package) and introduces a JWT-claim read requires:

- An explicit reviewer sign-off referencing this ADR (`ADR-001`).
- A justification in the PR description explaining why the claim read is NOT feeding an allow/deny or URL-signing-subject decision (e.g., telemetry tagging, rate-limit bucketing).
- A test covering the non-authz use case.

A PR reviewer who sees a JWT-claim read in those packages without ADR-001 sign-off MUST request changes.

### Lint gate (optional but recommended)

`scripts/check-jwt-in-exchange-authz.sh` is a grep-based pre-quality check that fails CI if any Go file under `src/exchange/internal/service/` or `src/exchange/internal/transport/` imports a JWT-parsing helper from a denylisted package set. The denylist is maintained inside the script and currently covers:

- `github.com/golang-jwt/jwt/v5`
- `github.com/lestrrat-go/jwx/v2/jwt`
- `github.com/coreos/go-oidc/v3/oidc` (for `IDToken.Claims` extraction)

The script is wired into `make quality` via the `file-length` target chain (runs on every local `make quality` and in CI).

If JWT parsing genuinely needs to happen in those packages for a non-authz reason (e.g., telemetry middleware), the script supports an inline waiver comment:

```go
// adr-001-allow-jwt: tenant-tag extraction for rate-limit middleware; not an authz input.
import "github.com/lestrrat-go/jwx/v2/jwt"
```

Waivers must include the `adr-001-allow-jwt:` prefix and a one-line justification on the same line as (or the line immediately preceding) the import. Every waiver is expected to be reviewed against this ADR.

---

## Notes

- The single entitlement biscuit and its mandatory per-request attenuation semantics are the subject of ADR-002. That ADR expands on Layer 3 here; this ADR treats the biscuit layer as a single conceptual box.

---

## Amendment (2026-04-21)

Two refinements to Layer 1, tightening both sides of the trust boundary so there is no trust-exempt internal hop and only one key-discovery shape:

1. **Every hop signs outbound; the Broker is a distinct RFC 9421 caller with its own keyID.** The original ADR implied Layer 1 runs "Agent → Broker"; in practice the Broker forwards to the Exchange and that second hop was previously unsigned. It is now signed with a broker-relay Ed25519 key whose keyID format is `broker.<instance>.<rotation>` (e.g., `broker.broker-local.v1`). Exchange treats the relay like any other caller — a single verifier, no internal-trust bypass — so audit logs distinguish relay hops from agent callers by kid prefix alone.
2. **Every component serves its public keys at `/.well-known/ramp-keys`; kid disambiguates purpose and rotation.** There is one JWKS endpoint per component. The Broker's JWKS carries both agent caller keys (kid prefix `agent.`) and its own relay key (kid prefix `broker.`); resource owners' JWKS carry entitlement-biscuit signing keys (kid prefix `entitlement.`); buyers' JWKS at `buyer_keys_url` carry delegation keys (kid prefix `delegation.`). Verifiers resolve by `(issuer URL, kid)` and never rely on the endpoint path to infer key purpose. This replaces the previously-divergent `/.well-known/ramp-agent-keys`, `/.well-known/biscuit-keys`, and `/.well-known/ramp-subscription-keys` endpoints. Per ADR-002 the IdP no longer mints any biscuit; identity facts travel as native JWT claims and require no separate JWKS hop.

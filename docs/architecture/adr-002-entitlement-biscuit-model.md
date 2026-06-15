# ADR-002 — Entitlement-Biscuit Model (single biscuit; mandatory per-request attenuation)

**Status:** Accepted (2026-04-21)
**Supersedes:** `docs/architecture/adr-002-two-biscuit-model.md` (previous draft — retracted; the identity-biscuit concept duplicated the JWT's job)
**Tracks:** ye6f-15 / agentic-content-access-e23e
**Companion documents:**
- `docs/architecture/adr-001-three-layer-auth.md` — why RFC 9421 + JWT + Biscuit coexist
- `docs/design/request-lifecycle.md` — end-to-end runtime flow
- Paused-methodology origin: original Biscuit choice (ADR-040) tracked in the `piarch` repo.

**See also:**
- `docs/architecture/adr-003-key-rotation-revocation.md` — rotation and revocation mechanics for the entitlement-biscuit signing key, buyer delegation key, and the opaque-URL discovery model for `buyer_keys_url` / `renewal_url`.
- `docs/protocol/ramp-protocol.md` — canonical implementer-facing narrative for how this biscuit shape composes with the renewal endpoint, keyed revocation list, and per-subscriber kid guidance, with worked examples for enterprise / platform-hosted / individual buyers.

---

## Context

The previous ADR-002 draft modelled authorization with **two** Biscuit artifacts on the wire — an identity biscuit (minted at IdP-time, carrying `user/email/org/identity_source`) and an entitlement biscuit (publisher-signed, carrying `subscriber_org/grants/valid_until`).

The 2026-04-21 design review surfaced that the identity biscuit duplicated the JWT's job. ADR-001 already pins JWT as the enterprise principal envelope (`sub`, `iss`, `aud`, `exp`) and the integration contract every corporate IdP exposes. A second artifact carrying the same principal facts — minted by the same IdP trust boundary — adds a key hierarchy, a `/.well-known/biscuit-keys` endpoint, and a mint webhook (Zitadel Actions v2 Target) without adding any authorization surface the JWT does not already provide.

Three forces pushed the model to a single-biscuit shape:

1. **The identity biscuit is redundant at the authorizer.** The authorizer needs `user` and `org` to bind delegation and enforce tenant rules. Both come from JWT claims (`jwt.sub`, `jwt.org`) that Exchange must already verify for SIEM-compatible envelopes (ADR-001 §Layer 2). Deriving them twice — once from the JWT, once from an identity biscuit — is two key hierarchies for one fact set.

2. **"Publisher" is one vertical.** RAMP serves resource owners across verticals — news publishers, data vendors, API providers, content marketplaces. The previous draft's `publisher(...)` Datalog fact and `/.well-known/ramp-subscription-keys` path embedded "publishing" into the protocol surface. Resource-owner-neutral terminology keeps the protocol honest about its scope and avoids retrofits when a data vendor or API provider is the issuer.

3. **Long-lived bearer capability needs a hard per-request cap.** An entitlement biscuit minted at contract-signing time (months-to-years TTL) is a capability token with a very large blast radius if stolen. The previous draft left attenuation as an MCP-shim responsibility but did not make it a wire-level invariant — a stolen authority biscuit, unattenuated, would grant full-contract access until `valid_until`. A mandatory per-request attenuation block with a ≤10-minute TTL bounds theft to a single session window and makes the buyer's delegation keypair the rotation handle.

This ADR locks in:
- A **single** entitlement biscuit on the wire, signed at authority-block level by the **resource owner**.
- **Mandatory per-request attenuation**, signed by a **buyer-side delegation key**, with a ≤10-minute TTL and a `sub(...)` fact bound to the JWT principal.
- **Resource-owner-neutral terminology** throughout (`resource_owner`, `subscriber_org`, `/.well-known/ramp-keys` hosted on each resource owner per ADR-001 amendment ye6f-11). "Publisher" appears only in demo examples.

---

## Decision

RAMP carries **one** Biscuit artifact on every authorized request — the **entitlement biscuit**. It is Ed25519-signed at the authority-block level by the resource owner, and carries a mandatory attenuation block signed by the buyer's delegation key.

### A. Authority block — resource-owner-signed, minted at contract time

The authority block is produced by the resource owner's contract-time minting tool (tracked as ye6f-13, `3hon`). It is handed out-of-band to the buyer along with the buyer-side delegation private key (see §C).

- **Issuer:** resource owner (e.g. `examplenews-as-resource-owner` in the demo; `reuters-data`, `ft-api`, `acme-dataset-vendor` in production).
- **Signing key:** resource owner's Ed25519 subscription key, distinct from any IdP key.
- **Pubkey discovery:** `https://<resource-owner-host>/.well-known/ramp-keys` (JWKS; see ADR-001 amendment ye6f-11 for the everyone-signs convention).
- **Lifetime:** short relative to contract term — `valid_until ≤ now + 7d` at mint time, re-issued periodically via `renewal_url`. This is a deliberate departure from the previous draft's months-to-years TTL; see "Consequences" below.
- **Authority-block facts:**

  ```
  resource_owner("examplenews");
  subscriber_org("acme");
  buyer_delegation_pubkey(hex("<ed25519 pubkey of buyer's delegation key>"));
  buyer_keys_url("<opaque HTTPS URL to buyer JWKS>");
  renewal_url("https://examplenews.com/ramp/issue");
  grants(["examplenews/read", "examplenews/search"]);
  contract_id("contract_acme_examplenews_2026");
  valid_from(2026-01-01T00:00:00Z);
  valid_until(2026-04-28T00:00:00Z);
  check if signed_by(buyer_delegation_pubkey);
  ```

  The final `check if signed_by(buyer_delegation_pubkey)` makes it structurally impossible for the biscuit to verify without a fresh attenuation block signed by the buyer's delegation key. Exchange cannot "accidentally" accept a bare authority block.

### B. Per-request attenuation block — MANDATORY, buyer-signed

Before every outbound call, the buyer-side (MCP shim or Broker) appends a fresh attenuation block signed by the buyer's delegation private key.

- **Minimum facts (Exchange MUST reject biscuits without these):**

  ```
  check if time() < 2026-04-21T09:56:00Z;   // <= now + 10m
  sub("user_bob_123");                      // binds to jwt.sub
  ```

- **Recommended narrowing:**

  ```
  check if operation("read");
  check if resource_starts_with("examplenews/pubs/2025/");
  ```

- **TTL cap:** Exchange rejects attenuation blocks whose latest `time() < T` check has `T - now > 10m`. This is a hard upper bound. Buyers are free to set it tighter (e.g. 60s for the current call) but not looser.
- **Signing requirement:** the block MUST be signed by the key whose raw public-key bytes match the `buyer_delegation_pubkey` fact in the authority block. Any other signer fails Exchange's gate A check (§E below).

### C. Buyer-side delegation key

One Ed25519 keypair per buyer organization. The keypair is the buyer's rotation handle.

- **Generation:** buyer generates locally at onboarding time (or when rotating).
- **Pubkey publication:** buyer hosts a JWKS at `buyer_keys_url`. The URL is **opaque** to the protocol — any HTTPS URL the buyer chooses.
  - Enterprise buyer with its own domain: `https://acme.com/.well-known/ramp-keys` (convention).
  - Agent platform hosting multiple buyers: `https://agent-platform.io/buyers/alice-personal/keys`.
  - Individual buyer using a wallet service: whatever URL the wallet exposes.
  - Dev/demo setup: a GitHub Gist JWKS URL is legal.
  The protocol recommends `{domain}/.well-known/ramp-keys` as a *convention* for predictable discovery, but resource-owner mint tools and Exchange treat the URL as opaque (fetch, parse JWKS, resolve kid).
- **Private-key distribution inside the buyer org:** distributed to every MCP shim instance of that org via the **same out-of-band channel** that delivers the entitlement biscuit. Typically a secrets manager entry or configuration bundle. The private key never leaves the buyer's administrative perimeter.
- **Pubkey baked into authority at mint time:** the resource owner's mint tool pulls the pubkey from `buyer_keys_url` at mint time and embeds its raw bytes in `buyer_delegation_pubkey(hex(...))`. **Pull, not push** — the well-known endpoint (or whatever URL the buyer hosts) is source of truth.
- **Rotation flow:** buyer rotates the JWKS at `buyer_keys_url` → later calls `renewal_url` → resource owner's mint tool fetches the current pubkey from the SAME URL → new authority block embeds the new key. No registry, no ceremony. The biscuit's delegation chain IS the registry.

### D. Org binding

The authority block's `subscriber_org(...)` fact is the buyer's tenant identifier at Exchange. Exchange asserts `jwt.org == subscriber_org`. Mismatch → `connect.CodePermissionDenied` with reason `"org mismatch"`.

`jwt.org` is the buyer's organization claim carried in the OIDC JWT (Zitadel emits it; enterprise IdPs emit it under various claim names, normalized at the JWT-verification layer). This binding prevents a stolen biscuit from being combined with a JWT from a different buyer organization.

### E. Authorizer

Exchange's authz path runs biscuit-lib chain verification first, then layers five service-level policy gates on top (tracked as ye6f-12, `x9pr`). The gates consume JWT-derived facts that are injected into the Datalog world at authz time, plus structural properties of the attenuation blocks that biscuit-lib does not enforce natively.

**Fact sources (Datalog world at authz time):**

1. **Authority-block facts (resource-owner-signed)** — `resource_owner/1`, `subscriber_org/1`, `buyer_delegation_pubkey/1`, `buyer_keys_url/1`, `renewal_url/1`, `grants/1`, `contract_id/1`, `valid_from/1`, `valid_until/1`.
2. **Attenuation-block checks** — applied by `biscuit-go` as part of `Authorizer.Authorize()`; narrowing-only is enforced at the library level.
3. **JWT-derived facts, injected at authz time** — `user(jwt.sub)`, `org(jwt.org)`. The Datalog world gets these as authority-equivalent facts trusted because the JWT was verified at the transport layer.
4. **Request facts** — `operation/1`, `resource/1`, `time/1`, `requested_resource_owner/1`.

**Service-level gates (applied in order; first failure is the denial reason):**

| Gate | Check | Denial reason |
|---|---|---|
| A — attenuation freshness | ≥1 block after authority; latest block has `time() < T` with `(T - now) ≤ 10m` and `T > now`; latest block has `sub(jwt.sub)`; latest block signed by `buyer_delegation_pubkey` | `"stale or missing attenuation"`, `"attenuation TTL > 10m"`, `"sub mismatch"`, `"attenuation not signed by delegation key"` |
| B — buyer-key freshness | fetch JWKS at `buyer_keys_url` (5m cache); `buyer_delegation_pubkey` MUST still be present | `"buyer key rotated or revoked"` |
| C — revocation | authority signing kid NOT in resource-owner revocation list; attenuation signing kid NOT in buyer revocation list | `"<kid> revoked"` |
| D — org binding | `jwt.org == authority.subscriber_org` | `"org mismatch"` |
| E — authority TTL | `authority.valid_until > now` | `"authority expired"` |

Gate specifics (discovery URLs, cache TTLs, JWKS shapes) are authoritative in the `x9pr` ticket; this ADR fixes the gate surface and ordering.

**Datalog query (after gates pass):**

```
allow if
  user($u),
  org($org),
  operation($op),
  resource($r),
  requested_resource_owner($ro),
  grants($g),
  contains($g, $scope),
  scope_covers($scope, $ro, $op),
  subscriber_org($so),
  $so == $org,
  time($t),
  valid_from($vf), $t >= $vf,
  valid_until($vu), $t < $vu;
```

Denial reason is the first-missing rule element — stable identifiers for audit-log correlation.

---

## Wire shape

Per ye6f-12 (`x9pr`), the single entitlement biscuit travels in an HTTP header, **not** in the proto body. The proto does not carry any biscuit field.

```http
POST /ramp.broker.v1.BrokerService/DiscoverResources HTTP/2
Host: broker:9090
Authorization: Bearer <Zitadel JWT>
X-RAMP-Entitlement-Biscuit: <base64url biscuit = authority + mandatory attenuation>
Signature-Input: sig1=("@method" "@target-uri" "content-digest" "authorization"
                      "x-ramp-entitlement-biscuit" "x-request-id");
                 keyid="mcp-shim-acme-01";created=1745222400;expires=1745222460
Signature: sig1=:<base64 Ed25519 sig>:
Content-Type: application/proto
```

RFC 9421 coverage extends over both the `Authorization` header (JWT) and the `X-RAMP-Entitlement-Biscuit` header, so request-integrity protection covers the full auth envelope. Biscuit fields are removed from `Requester.delegation`, `RAMPRequest`, `ResourceQuery`, and `TransactionRequest` in the proto update.

---

## Demo example (Examplenews as resource owner)

Examplenews is *one* resource owner in the demo stack. The terminology below uses `resource_owner("examplenews")` everywhere in the biscuit; "publisher" appears only in this example to anchor the demo narrative. Other resource owners (data vendors, API providers) use the same biscuit shape with their own identifiers — no protocol change.

Examplenews's contract-time CLI (tool from ye6f-13) mints an authority block with:
- `resource_owner("examplenews")`
- `subscriber_org("acme")`
- `buyer_delegation_pubkey(hex("…acme's Ed25519 pubkey bytes…"))`, pulled from `https://acme.com/.well-known/ramp-keys`
- `buyer_keys_url("https://acme.com/.well-known/ramp-keys")`
- `grants(["examplenews/read", "examplenews/search"])`
- `valid_until(now + 7d)`

Examplenews hands the biscuit and the companion buyer delegation keypair (if Examplenews generated it) or signs against acme's hosted pubkey (if acme generated it — the usual case) out-of-band to acme.

For each request, acme's MCP shim appends an attenuation block signed by acme's delegation key: `check if time() < now+60s`, `sub("user_bob_123")`, `check if operation("read")`, `check if resource_starts_with("examplenews/pubs/2025/")`.

---

## Consequences

### Positive

- **One key hierarchy per role.** Resource owners sign authority blocks. Buyers sign attenuation blocks. No IdP-side biscuit keypair; no `/.well-known/biscuit-keys` endpoint on idp-mint. ADR-001's three-layer model stays intact (JWT for identity, Biscuit for authz) with one less key set to rotate.
- **Authorizer gets fewer independent fact sources.** The Datalog world is authority + attenuation + JWT-derived + request — not identity-biscuit + entitlement-biscuit + attenuation + request. Simpler to reason about, simpler to audit-log.
- **Mandatory attenuation bounds long-lived-biscuit theft.** A stolen authority-only biscuit is unusable — the `check if signed_by(buyer_delegation_pubkey)` in the authority is structurally unverifiable without a fresh attenuation, and Exchange's gate A rejects stale/missing attenuation at the service layer. Theft blast radius is the attenuation TTL (≤10m) plus buyer-key rotation latency.
- **Resource-owner-neutral.** "Publisher" is one vertical. Data vendors, API providers, content marketplaces, or any resource owner can mint biscuits without the protocol carrying publishing-specific structure.
- **Opaque `buyer_keys_url` keeps buyer onboarding flexible.** Enterprise buyers use their own domain + `/.well-known/ramp-keys`. Agent platforms host JWKS per hosted buyer. Individuals use wallet services. No protocol hard-codes a domain assumption.
- **Revocation is split cleanly.** Resource owner revokes its own kids (rotating the mint key) independently of buyer revocation (rotating the delegation key at `buyer_keys_url`). Two independent handles for two independent compromise scenarios.

### Negative / costs accepted

- **Short authority TTL + periodic re-issuance.** The previous draft's months-to-years authority lifetime is replaced by ≤7-day TTL with renewal via `renewal_url`. This trades a new failure mode (renewal outage → Exchange rejects expired authority) for a much smaller theft blast radius. The tradeoff is deliberate — renewal outages degrade gracefully (buyer retries, operator alerts) while bearer-capability theft does not.
- **Buyer must host a JWKS somewhere.** Even for individual buyers, a stable HTTPS URL with a JWKS is required. Mitigated by "opaque URL" flexibility — wallet services, agent platforms, and Gists are all legal hosts in the protocol.
- **Mandatory attenuation adds one signing operation per request on the buyer side.** Ed25519 signing is cheap (microseconds); the MCP shim was already doing RFC 9421 signing, so the code path is warm. The pay-to-play cost for mandatory attenuation is an additional block allocation and chain serialization, measured in single-digit microseconds per call.
- **Gate C (revocation) introduces synchronous JWKS fetches at Exchange.** Mitigated by the 5-minute cache, but cold-start traffic sees up to two JWKS fetches per request (authority and attenuation revocation lists). Budget is acceptable for Exchange's SLO; Edge is unaffected (no biscuit verification at Edge).

### Out of scope for this ADR

- The exact JWKS-discovery protocol for revocation lists (tracked in ye6f-20 and referenced by gate C).
- Multi-resource-owner aggregators / reseller chains. The delegation chain supports them structurally; Exchange semantics for cross-resource-owner resolution are a v2 design question.
- Buyer-side delegation key management tooling (the buyer analogue of ye6f-13's mint tool). The demo uses a hand-managed keypair; production buyers will want a key-management service.

---

## Alternatives considered

### (a) Two biscuits (identity + entitlement) — previous ADR-002 draft — rejected

The earlier draft carried **two** biscuits on the wire: an identity biscuit minted by `idp-mint` via Zitadel Actions v2 PreAccessToken, and an entitlement biscuit from the publisher.

Rejected because:
- **Redundant with JWT.** The identity biscuit's `user/email/org/identity_source` facts are already present in the JWT (`jwt.sub`, `jwt.email`, `jwt.org`, `jwt.idp_alias`). ADR-001 requires JWT verification anyway for SIEM/gateway compatibility. Verifying the same facts twice through independent trust chains adds a key hierarchy with no authz-surface benefit.
- **Extra failure mode for no gain.** The identity biscuit requires the IdP mint webhook to be healthy at every login. `interruptOnError=true` on the Zitadel Actions Target makes a mint failure cause OIDC login failure. The biscuit path is a second reason an otherwise-valid login can fail, without a matching authz-surface justification.
- **Two `/.well-known/*` endpoints instead of one.** The previous draft had `/.well-known/biscuit-keys` on `idp-mint` and `/.well-known/ramp-subscription-keys` on publishers. Retiring the identity biscuit consolidates to `/.well-known/ramp-keys` on resource owners only (per ADR-001 amendment ye6f-11).

### (b) Single chain rooted at publisher with IdP-signed identity attenuation block — rejected

**Proposal:** one biscuit, authority block signed by the publisher, then an attenuation block signed by the IdP carrying identity facts, then buyer attenuation for narrowing.

Rejected because the trust direction is wrong: biscuit chain semantics require each subsequent block's signing key to be **authorized by the previous block's authority**. That would mean the publisher's authority block authorizes the IdP's signing key. Publishers have no basis to authorize a customer's IdP key — the IdP trust relationship lives at the buyer side, not the publisher side. Forcing it into the biscuit chain produces a structurally inverted trust model.

### (c) Biscuit-only, JWT unwrap at MCP shim — rejected

**Proposal:** strip the JWT at the MCP shim; forward only the Biscuit onward.

Rejected in ADR-001 (alternative (a) there). Enterprise SIEM, API-gateway, and service-mesh layers all key off `Authorization: Bearer <jwt>`; stripping the JWT breaks those integrations. OIDC/JWT is the corporate IdP integration contract; Biscuit-only requires every customer to build a bespoke token-exchange shim. See ADR-001 for the full rationale.

### (d) Optional per-request attenuation — rejected

**Proposal:** per-request attenuation is recommended but not required. Exchange accepts authority-only biscuits from buyers that haven't implemented attenuation yet.

Rejected because:
- **Long-lived biscuit theft becomes a full-contract breach.** An authority biscuit with (previously) months-to-years TTL, if stolen unattenuated, grants full contract access until `valid_until`. The attenuation TTL cap is the mechanism that bounds theft blast radius; making it optional eliminates the mechanism.
- **Inconsistent security posture across buyers is unauditable.** A resource owner would need to track per-buyer whether attenuation is enforced. That's a new per-buyer state machine at the authorization boundary, with the quiet failure mode that a buyer who stops sending attenuation is silently downgraded to "long-lived capability mode" without the resource owner noticing.
- **`check if signed_by(buyer_delegation_pubkey)` in the authority block is free to add.** Since the mint tool writes the authority block, adding the check costs one Datalog line per mint and makes "no attenuation" structurally unverifiable. The marginal cost of mandatory-everywhere is negligible compared to the audit benefit.

### (e) Buyer-side registry of delegation keys — rejected

**Proposal:** a central buyer-delegation-key registry service (RAMP-operated or federated) that Exchange queries to validate attenuation-block signing keys.

Rejected because the biscuit's delegation chain IS the registry. The authority block embeds the buyer's delegation pubkey (`buyer_delegation_pubkey(hex(...))`); Exchange verifies the attenuation block's signer against those bytes via gate A. No central state, no federated lookup, no registry sync protocol. Buyers rotate by updating their JWKS at `buyer_keys_url` and re-minting the authority (via `renewal_url`) — the in-biscuit registry advances with the chain.

---

## Related

- **ADR-001** (three-layer auth): JWT ≠ authz. The JWT carries principal identity (`jwt.sub`, `jwt.org`); the entitlement biscuit carries authorization. This ADR adjusts the Layer-3 row of ADR-001's summary table from "identity biscuit + entitlement biscuit" to "entitlement biscuit only".
- **ADR-040** (paused; Biscuit delegation tokens): locks in biscuit-v2 as the token format. This ADR applies that choice to one artifact with mandatory attenuation, rather than two.
- **ye6f-11** (`qrhi`, ADR-001 amendment): everyone-signs + `/.well-known/ramp-keys` convention hosted on each resource owner. This ADR consumes the `/.well-known/ramp-keys` endpoint for authority-block key discovery.
- **ye6f-12** (`x9pr`): single-biscuit-in-header + five Exchange policy gates. This ADR fixes the gate surface and ordering; `x9pr` is authoritative for URL shapes, cache TTLs, and JWKS structures.
- **ye6f-13** (`3hon`): resource-owner contract-time minting tool. Produces the authority blocks described in §A.
- **ye6f-14** (`bnk2`): retire `src/idp-mint/`. Deletes the identity-biscuit mint webhook (Zitadel Actions v2 Target, `/.well-known/biscuit-keys`) now that this ADR removes the identity biscuit from the wire.
- **ADR-003** (key rotation/revocation; tracked as ye6f-16): defines resource-owner and buyer revocation mechanics referenced by gate C.
- **`docs/design/request-lifecycle.md`** — authoritative for the runtime flow; updated to the single-biscuit + mandatory-attenuation story alongside this ADR.

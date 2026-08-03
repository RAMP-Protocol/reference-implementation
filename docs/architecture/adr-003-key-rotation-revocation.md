# ADR-003 — Key Rotation and Revocation Across the RAMP Stack

**Status:** Accepted (2026-04-21)
**Tracks:** key rotation and revocation.
**Drives:** the Exchange policy gates, the resource-owner mint, the renewal endpoint, the revocation-list endpoint, the protocol-spec update, the dedicated revocation signing key, and the per-subscriber kid convention.
**Companion documents:**
- `docs/architecture/adr-001-three-layer-auth.md` — why RFC 9421 + JWT + Biscuit coexist
- `docs/architecture/adr-002-entitlement-biscuit-model.md` — identity + entitlement biscuit split

---

## Context

The RAMP stack carries at least five distinct long-lived cryptographic keys per deployment, each with a different issuer, trust boundary, and compromise blast radius:

1. **Resource-owner subscription signing key** — publisher-side root (e.g. examplenews) that signs entitlement-biscuit authority blocks at contract-minting time.
2. **Buyer delegation key** — buyer-side root (e.g. acme) whose pubkey is embedded inside entitlement biscuits; buyer's own attenuation blocks are signed by this key.
3. **Agent RFC 9421 key** — per-agent (or per-MCP-shim) Ed25519 used to sign every HTTP request at the transport layer.
4. **Broker relay key** — Broker's outbound RFC 9421 key on the Broker→Exchange hop.
5. **Revocation-list signing key** — dedicated per-issuer Ed25519 used only to sign revocation-list responses (see §5c).

(A sixth, **Zitadel / OIDC JWT signing key**, rotates via standard OIDC JWKS mechanisms and is out of scope for this ADR.)

Two design forces shape the rotation story:

1. **Heterogeneous hosting.** Not every party controls a domain. Enterprise buyers do; individual buyers on an agent platform do not; small teams use wallet or key-manager services; developers run dev stacks with arbitrary URLs. A rotation model that mandates `{domain}/.well-known/ramp-keys` as the only legal location excludes everyone without a dedicated domain — which is the majority of the long-tail buyer market.
2. **No pubkey-sending between parties.** Every verifier must discover pubkeys by pulling from an URL published in the credential it is verifying. Push-based distribution (email the pubkey, pre-provision it, stash it in a config file) does not scale to a three-party stack (buyer ↔ resource owner ↔ exchange) with short rotation horizons, and it breaks the moment any party wants to rotate without coordinating.

The 2026-04-21 design review landed on an **opaque-URL + pull** model. This ADR pins that model down across every key type, specifies the revocation mechanism, and writes runbooks for each compromise scenario so operations are not improvised during an incident.

---

## Decision

### 1. Keys URLs are OPAQUE HTTPS references; `{domain}/.well-known/ramp-keys` is a RECOMMENDED convention, not a protocol requirement

Every keys URL in the RAMP protocol — `buyer_keys_url` in an authority block, `renewal_url`, the resource-owner's subscription-keys URL published in an entitlement biscuit, the Broker's consolidated RFC 9421 keys URL, the agent keys URL — is treated by verifiers as an **opaque `https://` reference**. Verifiers enforce exactly one thing about the URL: the scheme MUST be `https://`. There is no path validation, no host-matches-issuer check, no well-known-path assumption.

RAMP **RECOMMENDS** the convention `{domain}/.well-known/ramp-keys` for the keys JWKS and `{domain}/.well-known/ramp-revoked-keys` for the revocation list, for parties that control a domain and want a predictable location. The convention is discoverable, debuggable, and friendly to automated tooling. But it is not required. The protocol supports all of the following equally:

- **Enterprise buyer with own domain:** `https://acme.com/.well-known/ramp-keys` (uses the convention).
- **Agent platform hosting many buyers:** `https://agent-platform.io/buyers/alice/keys` (per-customer paths under a shared host).
- **Individual buyer using a wallet or key-manager service:** `https://wallet.example.com/pk/0x7a3f…` (whatever URL the wallet exposes).
- **Dev / demo stack:** `http://localhost:8080/keys.json` is allowed in non-production when TLS is mocked; production requires HTTPS.

**Rationale.** A well-known path mandate forces every RAMP participant to control a domain. That excludes individuals, small teams on hosted platforms, wallet users, and anyone behind a multi-tenant hosting provider. Recommending the path gives predictability for those who want it without baking a hosting model into the wire protocol.

This rule applies uniformly: every explicit URL field in the authority block or protocol spec is opaque. Future URL fields added by the spec inherit this rule by default unless the field's own spec explicitly says otherwise.

### 2. All pubkey discovery is PULL; no party ever pushes a pubkey to another party

**There is no pubkey-sending.** Every verifier acquires the pubkey it needs by fetching the URL the credential itself carries, not by receiving the pubkey out-of-band:

- **Resource-owner mint** (e.g. examplenews's mint) pulls the buyer's pubkey from `buyer_keys_url` at contract-signing time, and re-pulls on every renewal.
- **Exchange** pulls the resource-owner's pubkey from the URL carried in the entitlement biscuit and the buyer's pubkey from `buyer_keys_url` at verification time (cached per §4 below).
- **Broker** pulls the agent's pubkey from the consolidated Broker-hosted keys JWKS based on the `keyid` in the RFC 9421 signature.

**Rotation implication.** Because discovery is pull-only, rotation is a one-sided operation: the party holding the key updates the JWKS at its keys URL, and counterparties pick up the new pubkey the next time they verify a credential that references the new kid. The party rotating does not need to notify anyone, subject to the narrow exception below.

**The one renewal signal.** The resource-owner's `renewal_url` exists solely to tell the resource owner "a buyer has rotated its delegation key; please pull my new pubkey and re-issue the entitlement biscuit so future attenuation verifies under the new key." This is not a pubkey-push; it is a *trigger* for the resource owner to run its own pull. The actual pubkey transfer is still a pull by the resource-owner mint from the buyer's `buyer_keys_url`.

### 3. Rotation mechanics per key type

All rotations follow the same shape: **publish new kid alongside old, switch signing to new kid, remove old kid after grace window.** The window length and notification requirements differ per key type.

#### 3a. Resource-owner subscription signing key (e.g. examplenews)

1. Generate new keypair; assign a new kid (e.g. `examplenews.sub.2026q2`).
2. **Add** the new kid to the JWKS at the keys URL examplenews publishes; the old kid remains.
3. Start signing new entitlement biscuits under the new kid. Existing subscribers continue to hold biscuits signed under the old kid; they re-issue via the `renewal_url` flow on their natural renewal cadence (bounded by the 7-day authority TTL, §6).
4. **Remove** the old kid from the JWKS once all active contracts have been re-issued OR after the 7-day authority TTL elapses — whichever comes first. Any remaining biscuit signed under the old kid fails verification from that point.

No notification is required; subscribers discover the new kid via their normal verification path (pull from the keys URL). The old kid is served alongside the new one during the overlap window so in-flight verifications succeed.

#### 3b. Buyer delegation key (e.g. acme)

Buyer rotation requires a resource-owner round-trip because the buyer's pubkey is **embedded** in the entitlement-biscuit authority block (signed by the resource owner). Rotating the buyer key without a re-issue would break attenuation verification.

1. Generate new buyer keypair; add the new kid to the buyer's JWKS at whatever URL acme publishes (`https://acme.com/.well-known/ramp-keys`, or the agent-platform path, or the wallet URL).
2. Call each resource owner's `renewal_url` for every active contract.
3. The resource-owner mint pulls acme's fresh JWKS, selects the new kid, and issues a new entitlement biscuit embedding the new buyer pubkey.
4. Buyer removes the old kid from its JWKS when ready — typically once all active biscuits have been renewed. Exchange's 5-minute buyer-JWKS cache (§4) bounds the "old kid still accepted" window to 5 minutes past JWKS removal.

**Urgent-compromise variant:** buyer removes the old kid from its JWKS **immediately**, before re-issuing. Every Exchange instance that has the old JWKS cached will serve the cached old-kid response for up to 5 minutes, then refresh and reject all attenuation blocks signed by the compromised key globally. This is the mechanism by which a compromised buyer key is shut off within a bounded 5-minute window without coordinating with every resource owner.

#### 3c. Agent RFC 9421 key

Agent keys rotate via the Broker-hosted consolidated keys consolidated JWKS. The model is identical:

1. Agent generates new keypair; registers the new kid with Broker (Broker merges it into the JWKS it serves at its opaque keys URL).
2. Agent starts signing new outbound requests under the new kid.
3. After the migration window for in-flight requests (typically minutes; RFC 9421 signatures are short-lived), the agent asks Broker to remove the old kid.

Broker's keys URL is opaque per the same rule as every other party — Broker chooses where to host; verifiers (Exchange, Edge) pull from it. No well-known-path requirement.

#### 3d. Broker relay key

Identical pattern. Broker generates a new relay keypair, publishes the new kid at whatever keys URL Broker has chosen, starts signing Broker→Exchange requests under the new kid, and removes the old kid once the in-flight window has drained.

#### 3e. Revocation-list signing key

See §5. This is a dedicated key (use=`revoke`) separate from the issuer's subscription-signing key. It rotates via the same add-new-kid / remove-old-kid pattern, published in the same JWKS (or a sibling discovery path per the protocol-spec decision), with the discriminator being `use=revoke` or an equivalent marker.

#### 3f. Zitadel / OIDC JWT signing key (out of RAMP scope)

Rotation follows standard OIDC JWKS semantics: Zitadel publishes the next kid at `/.well-known/jwks.json` before it starts signing under it; verifiers refresh JWKS on kid-miss. No RAMP-specific guidance needed.

### 4. Verifier-side cache TTL

| Credential | Cache TTL | Refresh trigger |
|---|---|---|
| Resource-owner subscription JWKS | 24 h | Kid miss; verification failure (one re-fetch) |
| Buyer JWKS (at `buyer_keys_url`) | **5 min** | Expiry; kid miss; verification failure |
| Broker keys JWKS (agent + relay) | 24 h | Kid miss; verification failure |
| Revocation list per issuer | **5 min** | Expiry; generation decrease (treated as rollback, reject) |
| Zitadel / OIDC JWKS | 24 h | Standard OIDC behavior |

The buyer JWKS gets a tighter 5-minute cache specifically so that urgent buyer-key revocation (§3b) takes effect globally within minutes without requiring each resource owner to notify every Exchange instance.

### 5. Revocation is KEYED, not contract-keyed

Revoking an entire `kid` invalidates every biscuit ever signed under it in a single O(1) verifier check. Revoking a list of `contract_id`s requires a lookup per authz decision and a revocation list that scales with contract volume; in a healthy deployment that list can reach tens of thousands of entries and never materially helps with compromise (if one contract is "revoked" while the signing key is still trusted, any holder of that key can re-mint the same `contract_id`).

The model is therefore: **compromise rotates the key and revokes the old kid.** Individual-contract invalidation is a contract-lifecycle concern, not a cryptographic-revocation concern, and lives in Exchange's subscription state, not in the revocation list.

#### 5a. Endpoint model

The revocation-list URL is **OPAQUE** per the same rule as the keys URL. RAMP RECOMMENDS the convention `{domain}/.well-known/ramp-revoked-keys` for parties that want a predictable location, but any `https://` URL works. In practice the discovery mechanism (pinned by the protocol spec) is one of:

- The issuer's keys JWKS carries a top-level `"revocation_url"` metadata entry pointing to the revocation endpoint, OR
- Verifiers use the sibling-path convention `{keys_url_with_/ramp-keys_replaced_by_/ramp-revoked-keys}` as a default.

Either way, no well-known path is mandatory; the JWKS metadata entry is authoritative when present.

#### 5b. Response format

```json
{
  "issuer": "examplenews.com",
  "generation": 42,
  "revoked": [
    {"kid": "examplenews.sub.2025q3", "revoked_at": "2026-04-20T14:22:11Z"},
    {"kid": "examplenews.sub.2025q4.subscriber-acme-01", "revoked_at": "2026-04-21T08:00:00Z"}
  ],
  "signature": "<base64url ed25519 signature over canonical JSON of {issuer, generation, revoked}>",
  "signing_kid": "examplenews.revoke.2026"
}
```

- `issuer` — identifier the verifier matched against the biscuit's issuer.
- `generation` — monotonically increasing integer. Verifiers MUST reject a fetched list whose generation is **lower** than the last one they cached for this issuer; this prevents rollback attacks where an attacker with a stale cached copy tries to resurrect revoked kids.
- `revoked` — list of `{kid, revoked_at}` entries. Order is not significant; `revoked_at` is informational and not used in verification.
- `signature` — Ed25519 signature over the canonical-JSON serialization of `{issuer, generation, revoked}`. Canonicalization rules: UTF-8, sorted object keys, no insignificant whitespace, arrays in the order written.
- `signing_kid` — kid of the **dedicated revocation signing key** that produced the signature. This kid appears in the issuer's keys JWKS with `use=revoke` (see §5c).

#### 5c. Dedicated revocation signing key

The revocation list is signed by a **separate** key from the issuer's subscription signing key. The issuer's keys JWKS exposes both — the subscription signing key (used to sign biscuits) and the revocation signing key (used to sign revocation lists) — distinguished by the `use` field: `use=verify` for the subscription signing key, `use=revoke` for the revocation signing key. Verifiers select by `(kid, use)` and MUST NOT chain-verify a biscuit against a `use=revoke` entry, nor verify a revocation-list signature against a `use=verify` entry.

##### Why dedicated revocation key

The dedicated revocation key is the cryptographic mechanism that keeps the revocation channel functional under signing-key compromise. Five forces motivate the split:

1. **Compromise must remain revocable.** If the subscription signing key is compromised, the attacker can mint arbitrary biscuits. If the *same* key also signed revocation lists, the attacker could sign a "clean" revocation list that omits the compromised kid, making the compromise **un-revocable** until the key itself is rotated through an out-of-band procedure. The revocation list is the only online lever shorter than the 7-day authority TTL (§6), so removing it removes the only sub-7-day mitigation.
2. **Different operational environments.** The two keys SHOULD live in different operational environments — different HSM slot, different signing machine, different access policy, ideally different on-call rotation. The signing key is exercised continuously at contract-issuance time and must be reachable from automation; the revocation key is exercised only during incident response and can sit behind tighter access controls (e.g. break-glass-only). A breach of the signing-key environment does not automatically yield the revocation key.
3. **Different rotation cadences.** The signing key rotates on a quarterly or per-incident schedule; the revocation key can rotate annually or only on revocation-key-specific compromise. The split lets each key follow the cadence that fits its risk profile rather than forcing a single rotation cycle.
4. **Auditability.** Every signature the revocation key produces is by construction a revocation event. A monitoring system that watches the revocation key for any signing activity at all sees only true positives — there is no signing-list noise to filter out. With a shared key, every routine signing event would have to be classified.
5. **Audience separation.** Verifiers know in advance which `use` value to expect for which signature. A revocation-list verifier that receives a `signing_kid` resolving to a `use=verify` entry MUST refuse to validate the list; a biscuit-chain verifier that receives a kid resolving to `use=revoke` MUST refuse to chain-verify. These remain design requirements: the shared JWKS package that enforced them was deleted, and nothing enforces them today. The `use` field gives both sides an unambiguous typing rule and makes confused-deputy attacks impossible at the API surface.

**Rotation.** The revocation key rotates by the same add-new-kid / remove-old-kid pattern as every other key. If the revocation key itself is compromised, the issuer publishes a rotated revocation key (under a new kid with `use=revoke`) and the next revocation-list fetch uses the new kid. Verifiers that cached the old revocation-key pubkey reject the next-generation list (signed by the new kid not in cache) with a "kid miss" and refresh.

**Implementation status.** The `use=verify` / `use=revoke` split described here is no longer how keys are published: the shared JWKS package that resolved by `use`, and the Exchange-side delegation resolver that applied the same filter to the manifest schema, were both deleted. Key material is now published uniformly and revocation is a separate signed document rather than a per-key `use` discriminator. Of the issuer-side helpers, only `scripts/gen-buyer-delegation-key.sh` survives, still generating a verify/revoke pair as one JWKS; the resource-owner counterpart was deleted with the subscription fixtures, and `scripts/gen-examplenews-publisher-key.sh` is the surviving publisher-side generator.

### 6. Authority TTL ≤ 7 days is REQUIRED; renewal is mandatory

Every entitlement-biscuit authority block MUST carry an `expires_at` fact set to no more than **7 days** from issuance. Verifiers reject any authority block with `expires_at > now + 7d` or missing `expires_at` entirely. Buyers MUST renew via the resource-owner's `renewal_url` before expiry.

**Rationale — bounded compromise window.**

- Without any online signal, a compromised key can mint biscuits that remain valid until the longest outstanding authority TTL, at worst **7 days**.
- A compromised-key revocation-list publication shortens this to **5 minutes** (the revocation-list cache TTL; §4) for verifiers that reach the revocation endpoint.
- A JWKS rotation (removing the old kid from the keys URL) shortens this to 5 minutes for the buyer-key case (5-minute buyer-JWKS cache; §4) and 24 hours for the resource-owner-key case (24-hour subscription-JWKS cache; §4), unless paired with a revocation-list publication which overrides both.

Seven days is the hard ceiling on "compromise-to-natural-expiry without any online check." Operations MAY choose shorter TTLs per tenant (24 h or 1 h for high-sensitivity publishers); 7 days is the protocol-wide cap.

### 7. Per-subscriber kid is an operational best practice

The resource-owner mint SHOULD assign a **distinct kid per subscriber** at contract-signing time — e.g. `examplenews.sub.2026q2.subscriber-acme-01`, `examplenews.sub.2026q2.subscriber-contoso-07` — even though each is derived from the same subscription signing root. This is an operational convention, not a protocol requirement; a shared kid across all subscribers is valid.

**Why it matters.** Per-subscriber kids let an issuer revoke a single customer's biscuits (e.g. contract terminated, customer in breach, customer's account compromised) without affecting every other customer of the same publisher. The revocation list entry for `examplenews.sub.2026q2.subscriber-acme-01` invalidates exactly that customer's biscuits in O(1); a shared kid would force a wholesale publisher-wide rotation for any single-customer incident.

The per-subscriber kid is derived deterministically from the root key and subscriber ID (HKDF with subscriber-ID salt, or a similar per-kid derivation) so the issuer does not need to store 10,000 independent keypairs.

---

## Consequences

### Positive

- **Broad hosting support.** Buyers on dedicated domains, on multi-tenant platforms, behind wallet services, and in dev/demo all use the same wire-level URL semantics. The convention is there for those who want it; the opaque-URL rule is there for everyone.
- **Rotation is one-sided.** Every party rotates on its own schedule by updating its JWKS at its keys URL. The only cross-party coordination is the `renewal_url` call for buyer-delegation rotation, which re-uses the already-mandatory renewal flow.
- **Compromise is bounded.** Seven days without any online signal; five minutes once the revocation list or buyer JWKS is updated. Operations have clear levers per severity level.
- **Revocation scales with kids, not contracts.** A 10,000-subscriber publisher with per-subscriber kids has a revocation list proportional to active incidents, not to contract volume. A shared-kid publisher has an even smaller list.
- **Revocation survives signing-key compromise.** Dedicated revocation signing key keeps the revocation path alive when the signing path is compromised.
- **No privileged notification channel.** Pull-based discovery means no email list, no webhook fanout, no "please add our new pubkey to your config" ticket flow.

### Negative / costs accepted

- **Every verifier fetches JWKS and revocation list at runtime.** The cache TTLs (§4) bound this, but the p99 verification that hits cache-miss pays an HTTPS round-trip. Cold-start verification on Edge is already a hard-real-time concern (Edge answers 503 on a cache miss rather than serving unverified); other verifiers accept the occasional miss latency.
- **Five runbooks instead of one.** Each key type has its own compromise procedure (§Runbooks below). Operations documentation is larger but the per-runbook steps are short and mechanical.
- **Revocation generation monotonicity is a discipline.** Issuers MUST bump `generation` on every revocation-list publication; a bug that re-publishes a stale list with the prior generation number will be rejected by verifiers as a rollback. This is the intended behavior — verifiers treat rollback as hostile — but it means issuer tooling must persist the last generation across restarts.
- **Per-subscriber kid is derivation-heavy.** Mint code must implement deterministic per-kid derivation (HKDF or similar). This is one-time engineering cost; runtime cost is negligible.

---

## Runbooks

### Runbook A — Examplenews subscription signing key compromise

**Scope:** the per-publisher Ed25519 root that signs entitlement-biscuit authority blocks for all examplenews subscribers (or, with per-subscriber kids, the derivation root).

1. **Declare incident.** Page on-call; open an incident ticket referencing this runbook.
2. **Generate replacement keypair** under a fresh kid (e.g. `examplenews.sub.2026q2.incident-2026-04-21`). Rotate it into the mint HSM/KMS slot that issues entitlement biscuits.
3. **Publish the new kid** in the examplenews keys JWKS alongside the compromised kid. Verifiers will start seeing the new kid on subsequent refreshes (24 h cache at most).
4. **Publish a signed revocation list** including the compromised kid. Bump `generation`. Sign with the dedicated revocation key. Every verifier refreshes within 5 minutes and rejects all biscuits under the compromised kid globally.
5. **Re-issue every active contract.** For each subscriber, either wait for natural renewal (≤ 7 d) or proactively invoke the renewal flow. With per-subscriber kids, only the compromised kid's subscriber is affected; without per-subscriber kids, every subscriber must be re-issued.
6. **Remove the compromised kid from the keys JWKS** after the re-issue campaign completes and the 7-day authority TTL has elapsed — whichever is sooner.
7. **Post-incident:** audit which contracts were issued under the compromised kid; check for anomalous biscuit-issuance events in the logs of the compromised signer.

### Runbook B — Acme buyer delegation key compromise, enterprise-domain case

**Scope:** acme controls `acme.com` and publishes its JWKS at `https://acme.com/.well-known/ramp-keys`.

1. **Declare incident.** Page on-call; open an incident ticket.
2. **Generate replacement buyer keypair** under a fresh kid (e.g. `acme.del.2026-04-21-incident`).
3. **Remove the compromised kid from `https://acme.com/.well-known/ramp-keys` immediately.** Exchange's buyer-JWKS cache (5 min) will expire within 5 minutes; all attenuation blocks signed by the compromised key are rejected globally from that point.
4. **Publish the new kid** in the JWKS.
5. **Call the `renewal_url` for every active contract.** Resource-owner mints pull the fresh acme JWKS, select the new kid, and re-issue entitlement biscuits embedding the new buyer pubkey. Acme's agents resume with the re-issued biscuits.
6. **Post-incident:** scan audit logs for any request signed by the compromised kid between issuance and JWKS removal; coordinate with affected resource owners on breach notification.

### Runbook C — Acme buyer delegation key compromise, platform-hosted case

**Scope:** acme is an individual or small team hosted on `agent-platform.io`; acme's keys URL is `https://agent-platform.io/buyers/acme/keys`.

1. **Acme declares incident** to the agent platform's incident channel.
2. **Agent platform rotates acme's keypair** — generates a fresh kid under acme's per-customer path. This is a platform-operator action; acme does not run its own domain or HSM.
3. **Agent platform removes the compromised kid** from `https://agent-platform.io/buyers/acme/keys` immediately. 5-minute buyer-JWKS cache bounds global rejection to ≤ 5 min.
4. **Agent platform publishes the new kid** in the same URL.
5. **Agent platform calls the `renewal_url` for every active contract** acme holds. Resource-owner mints pull from `https://agent-platform.io/buyers/acme/keys`, see the new kid, re-issue.
6. **Post-incident:** platform-wide audit — because the hosting is multi-tenant, check whether the compromise originated in the platform infra itself (in which case every customer may be affected, not just acme).

### Runbook D — Agent RFC 9421 key compromise

**Scope:** a single agent's request-signing keypair (Ed25519 used in `Signature-Input`).

1. **Declare incident.**
2. **Generate replacement agent keypair** under a fresh kid.
3. **De-register the compromised kid from the Broker-hosted consolidated keys JWKS**. Broker's keys URL drops the compromised kid.
4. **Register the new kid** in the same JWKS.
5. **Rotate the keypair on the agent host** so the agent starts signing with the new kid immediately. In-flight requests signed by the old kid fail verification at Broker/Exchange as soon as the old kid is gone from the JWKS (cache TTL bounds this to 24 h; operations MAY force-refresh by calling Broker's reload endpoint).
6. **Post-incident:** audit the agent host for persistence; rotate any derived credentials the agent held.

Because RFC 9421 signatures are short-lived (sub-minute `created`/`expires` windows are typical), the practical compromise window is very short even without JWKS rotation — once the old key is removed from the JWKS, no forged signature can be crafted that will survive the RFC 9421 freshness check.

### Runbook E — Broker relay key compromise

**Scope:** Broker's outbound Broker→Exchange RFC 9421 signing key.

1. **Declare incident.**
2. **Generate replacement broker-relay keypair** under a fresh kid.
3. **Remove the compromised kid from Broker's consolidated keys JWKS.** Exchange's 24 h JWKS cache will refresh; force-refresh available via ops signal.
4. **Register the new kid** in the same JWKS.
5. **Rotate the keypair in the Broker deployment** (rolling restart with the new key mounted from KMS/secret store). Broker starts signing with the new kid.
6. **Verify Exchange traffic continuity.** Exchange rejects requests signed by the compromised kid once JWKS refreshes; there is a brief window (up to the JWKS cache TTL) where in-flight verifications may still use the cached old kid, but any forged request will fail once the JWKS refreshes.
7. **Post-incident:** audit Broker's request log for anomalous Exchange calls during the compromise window.

---

## Alternatives considered

### (a) Mandate `{domain}/.well-known/ramp-keys` as the only legal URL (rejected, 2026-04-21)

**Proposal:** Every RAMP participant MUST publish its keys JWKS at `{their_domain}/.well-known/ramp-keys`. Verifiers derive the URL from the issuer identifier rather than reading it from the credential.

**Rejected because:** participants without a domain — individuals on agent platforms, wallet users, small teams on multi-tenant hosting — cannot comply. Forcing domain ownership as a prerequisite excludes the long-tail buyer segment entirely, and pushing those buyers onto an agent-platform workaround already requires the opaque-URL mechanism (the platform's per-customer path). Once opaque URLs are in the protocol for the platform case, mandating the well-known path for everyone else adds no security and removes flexibility. Recommending the convention captures the ergonomics without the exclusion.

### (b) Push-based pubkey distribution (rejected)

**Proposal:** When a party rotates its key, it POSTs the new pubkey to every counterparty's registered endpoint. Verifiers trust the endpoint registry rather than pulling from a credential-carried URL.

**Rejected because:** (1) it requires every party to run a signed-webhook receiver and a trust registry; (2) a three-party stack (buyer ↔ RO ↔ Exchange) multiplies the fanout; (3) a push failure — missed webhook, wrong endpoint — creates a silent trust gap the verifier does not notice until the next verification fails. Pull-based discovery makes the credential itself the source of truth: if a verifier can verify the credential, it has the right pubkey by construction.

### (c) Contract-keyed revocation list instead of keyed revocation (rejected)

**Proposal:** Revocation list carries `contract_id`s rather than kids. Revoking a single subscriber revokes only that subscriber's contract.

**Rejected because:** (1) revocation-list size scales with contract volume, not with incident count — a 10,000-subscriber publisher would publish 10,000-entry lists routinely; (2) verification cost per request becomes O(n) in list size rather than O(1); (3) compromised-key incidents still require rotating the kid and re-issuing, and the contract-keyed list doesn't reduce the blast radius in that case. Per-subscriber kids (§7) get the fine-grained revocation benefit without the list-size or verification-cost penalties.

### (d) Shared signing + revocation key (rejected)

**Proposal:** Issuer uses one Ed25519 key for both signing biscuits and signing revocation lists.

**Rejected because:** key compromise becomes un-revocable. An attacker with the single key can mint arbitrary biscuits AND sign a revocation list that excludes the compromised kid. A dedicated revocation key (operationally isolated from the signing key) is the mechanism that keeps the revocation path alive under signing-key compromise.

### (e) Long-lived authority TTL with online revocation checks (rejected)

**Proposal:** Authority TTL is 30 days or 90 days; compromise is handled entirely via the revocation list.

**Rejected because:** a verifier that cannot reach the revocation endpoint (network partition, issuer downtime) would either fail-open (accept the biscuit indefinitely — unacceptable) or fail-closed (block all authz during the outage — denial of service). The 7-day TTL caps the worst-case compromise window even when the revocation path is unavailable, giving Exchange a safe fail-open default that is bounded by a short natural expiry.

---

## Related

- **ADR-001** (three-layer auth): RFC 9421 + JWT + Biscuit coexistence. This ADR specifies how each of those layers' keys rotate.
- **ADR-002** (entitlement-biscuit model): defines the authority-block structure that carries `buyer_keys_url` and `renewal_url`. This ADR specifies how those URLs are discovered and how rotation at their endpoints flows through to Exchange.
- **Broker consolidated keys JWKS**: sources the agent and broker-relay kids referenced in Runbooks D and E.
- **revocation list endpoint**: implements §5 on the issuer side.
- **RAMP protocol spec update**: pins the discovery mechanism (JWKS metadata entry vs sibling-path convention) for the revocation-list URL.
- **dedicated revocation signing key**: implements §5c on the issuer side.
- **per-subscriber kid**: implements §7 on the resource-owner mint side.

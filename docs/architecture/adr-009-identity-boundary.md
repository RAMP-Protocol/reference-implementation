# ADR-009 — Identity Boundary: Exchange vs Billing

**Status:** Accepted (2026-06-02)

---

## Context

The Exchange and the Billing adapter both reason about "who is acting," but the two views must not collapse. Without an explicit boundary: registration semantics drift (does an unknown agent need a billing account before it can call?); agent identity gets re-scoped per tenant (which forces N updates per key rotation against a single `/.well-known/ramp.json`); and per-subsystem key caches drift, so a key rotated within the 5-minute window is accepted on one side and rejected on the other. Compounding this, most RAMP traffic — free resources, subscription-token paths, discovery probes — never moves money and so never touches the Billing adapter at all.

---

## Decision

### D1 — The Exchange's `agents` table is the cryptographic source of truth

The `ramp.agents` table (migration `000001_init`) is the deployment's authoritative store of which keys this Exchange accepts signatures from and what role each key plays (AGENT / BROKER / HUMAN_TOOL / SERVICE / DELEGATED / RESEARCH). It is not an account ledger: no balance, no quota, no reservation state. The Exchange's authorization layer (`src/exchange/internal/service/authz.go` — `resolveCaller`, `authorizeForAgent`) reads it on every request. An unknown keyID is `Unauthenticated`; a known one maps to a `Caller` whose role decides whether the transaction is self-acting (CallerAgent) or broker-on-behalf (CallerBroker, gated by `tenants.allow_broker_relay` per ADR-006). Separating cryptographic identity from financial state means the Exchange refuses forged signatures without consulting the Billing adapter — the cryptographic boundary lives entirely inside the Exchange, hydrated from `/.well-known/ramp.json` per ADR-003's pull-only discovery.

### D2 — Registration is lazy; Billing creates accounts on first Authorize, when it needs an account at all

There is no mandatory pre-registration ceremony. A new agent presenting a valid signature against a key in its `/.well-known/ramp.json` MAY consume immediately. The first inbound request whose keyID is absent from `ramp.agents` triggers the Exchange's registration path — pull the key, persist the row, proceed with authorization.

The Exchange recognizes exactly three call-paths; everything else is refused at authz:

- **Free resources** (`unit_cost == 0`): no `Authorize`, no Billing-side identity, no TigerBeetle account.
- **Biscuit-bearing requests**: the request carries a biscuit (issuer + consumer) granting scoped access — subscription tokens, attenuated delegations, sub-delegated chains. The Exchange verifies the biscuit; the Billing adapter is not in the call path. All authorization inside RAMP is biscuit-based: any external concept (API key, OAuth token, OIDC session) maps to or embeds into a biscuit at the protocol boundary, and the IdP bridge (Zitadel and friends) is exactly that mapping layer. There is no path that bypasses the biscuit.
- **Paid one-shot transactions**: `Authorize` is called. Per the TigerBeetle ticket, the adapter does lazy account creation — `lookup_accounts` returns nothing, `create_accounts` runs against the derived account ID, `Authorize` proceeds. First paid transaction is also the agent's registration in Billing.

On the free path the Exchange bypasses the billing adapter **entirely**: because no `Authorize` runs, none of the adapter's gates — balance, quota, or agent-eligibility — apply. That is what "no Billing-side identity" means concretely: a free resource consumes no quota and requires no billing account. (A balance-bearing adapter's own zero-charge branch may still enforce quota/eligibility, but the service never reaches it for a price-zero term — `authorizeBilling` floors quantity to ≥1 and the price-zero short-circuit skips the adapter, so that branch serves only a direct caller passing a genuine zero charge, e.g. a non-zero `unit_cost` at quantity 0.)

Free-ness is keyed off `unit_cost`, not `rate`. `unit_cost` is the normalized, signature-covered charge basis (an explicit `unit_cost` overrides the `rate` fallback in the pricing projection), so a publisher may advertise a headline `rate` (e.g. `5.00`) while setting `unit_cost = 0` for free execution — internally consistent and publisher-controlled, not a vulnerability.

Settlement is operator-mediated: invoice via Stripe (or equivalent), apply a manual credit into TigerBeetle. No protocol-driven onboarding flow mints a balance. A pre-registration ceremony would either gate free/biscuit paths behind irrelevant billing setup or fork registration on an intent the agent cannot reliably declare up front.

### D3 — Agent identity is global, not tenant-scoped

The `agent_id` is a globally-unique, domain-shaped identifier. For a self-hosted agent it equals their own domain (`examplenews.com`); for a "domainless" agent it is a subdomain on a registry that hosts `/.well-known/ramp.json` on the agent's behalf (`agent-xyz.registry.example.com`). Either shape, the discovery anchor and the identifier resolve the same way, and `(agent_id, domain)` is one pair across every tenant of this Exchange. The genuinely-domainless case — keys passed inline in the request with no DNS at all — would need a proto change (a `Requester.public_keys` carrier or equivalent safe inline channel) and is deferred.

- **Wire**: `Requester.id` is the identifier; `Requester.domain` is the discovery anchor. For both self-hosted and registry-hosted agents these are the same domain shape; the split exists so a future inline-key variant can populate `Requester.id` without a DNS-resolvable `Requester.domain`.
- **Repository**: `ramp.agents.agent_id` is the PK with no `tenant_id` column. Per-tenant tables (`transaction_log`, `reporting_obligations`, `catalog`) reference it directly. The tenant-isolation rule applies to those per-tenant tables, not to `agents` itself — it governs list/scan queries that need tenant scoping, and a PK lookup of a global identity is not a violation.
- **Billing**: a TigerBeetle account derived from `sha256("agent:" + agent_id)` is similarly global. A Phase-2/3 multi-currency extension shards per `(agent_id, ledger)`, never per `(agent_id, tenant_id, ledger)`.

**On per-agent-id vs per-company billing.** The protocol distinguishes two principals on the wire — the agent (`Requester.id` / `Requester.domain`) and a delegated principal (`Delegation.principal_id` / `principal_domain`, see [authentication](https://ramp-protocol.org/protocol/authentication/) and proto §927 `REQUESTER_TYPE_DELEGATED` + §957 `Delegation`). `principal_id` per the proto is a user (`user@acme.com`), not the company itself. So `Delegation` alone does not get us to "one billing account per acme.com." The "company is acme.com" identity is what we want for company-wide billing or company-wide subscriptions, and the protocol does not carry that today. The v1.0-production branch explored deriving it at biscuit-mint time (the IdP that authenticates the user knows the org domain → embed it into the biscuit as a verifiable claim); the integration surface is large and the work did not make this revision. For company-wide subscriptions that derivation path is sufficient (the biscuit carries the org claim; the Exchange checks it). For company-wide per-access billing without subscriptions, the protocol would need an explicit `org_domain` field in the request itself — a proto change deferred to a future ADR. Until either lands, the current reality is `agent == principal`, `agent_id` is the billing principal, and "company" is not modeled at the protocol level. Consolidation under one company happens either off-platform (one Stripe customer aggregates multiple agent_ids' invoices) or via the registry-host pattern (one registry domain mints `agent-1.acme.com`, `agent-2.acme.com`, etc., rolling up to a single off-platform account).

Identity follows the discovery anchor. Making addressability narrower than the protocol's own naming would create private re-namespacing whose only effect is to multiply administrative work; cross-tenant operator analytics ("how many transactions did agent X make this month") collapse to a single-key join.

### D4 — Key rotation follows the protocol's overlap-window model; both sides read the same cache, pulled independently per Exchange

Both sides — the Exchange's signature verification and any Billing-adapter operation that verifies a signed payload — discover keys via the same pull-only mechanism per ADR-003: opaque `https://` URL, pulled at verification time, cached short (5 minutes for agent/broker, 24 hours for resource-owner subscription keys, per ADR-003 §4).

**Overlap window.** The protocol's rotation model (ADR-003 §3) is "publish the new key alongside the old, switch signing to the new, remove the old after the grace window." The Exchange treats the publisher's Web Bot Auth directory (`WBAFile.keys`) as a set: any key whose `[not_before, not_after)` covers `Clock.Now()` is accepted (per ADR-008 D1, the clock is a port). The 5-minute TTL bounds the lag between "operator removed the key from the directory" and "last Exchange still accepts a signature under it"; ADR-003 §3b walks the urgent-compromise variant. Keys are named by RFC 7638 thumbprint rather than by `kid` — the protocol carries no `kid` on a JWK — but the set-with-window semantics is unchanged, and is what `rampwellknown.ActiveKeys` implements.

**Federation by independent re-pull, not central registry.** Each Exchange independently pulls `/.well-known/ramp.json` from the agent's `Requester.domain` and caches per ADR-003 §4. No shared agent registry across Exchanges — matching the protocol's pull-only philosophy (ADR-003 §1) and the ActivityPub precedent: every party publishes, every verifier pulls, nobody pushes. Each Exchange's `ramp.agents` row is a private cache of the authoritative document. Two Exchanges X and Y operating against the same agent each accept a rotated kid by T+5min within their own independent windows; revocation propagates the same way.

**Failure mode.** When the agent's domain is temporarily unreachable, each Exchange continues to serve cached values until the TTL elapses; first-touch on a never-cached agent returns `KindUnavailable`. Operators wanting high-availability identity for domainless agents use the registry-host pattern (proto §1664-1670) — a registry hosts the agent's `WellKnownManifest`, the agent sets `Requester.domain` to the registry host. The registry serves documents; it does not issue identities.

**Publisher rotation.** Publishers sign two distinct surfaces — outbound requests to the Exchange (e.g. `PushResources`, RFC 9421 key) and publisher-issued biscuits granting subscription-token access. Both rotate via the same `WellKnownManifest` + 5-minute-cache model. The Exchange separately holds the publisher-tenant's signing keys (`tenants.ed25519_key_ref`, `tenants.rsa_key_ref`) used to mint offer signatures and signed URLs; their rotation cadence is operator-internal and orthogonal to inbound-signature rotation.

**Billing side.** The Billing adapter does not currently verify agent or publisher signatures on the hot path (Authorize / Record / Release / Refund are called by the in-process service that has already authenticated). When the adapter starts verifying signed payloads, it MUST consume keys from the same source as the Exchange — either via a shared `keys` cache port or via an Exchange-side endpoint that does verification on its behalf. No Billing-local keystore that drifts from the Exchange's view.

### D5 — The cross-subsystem link is the global `agent_id`; `transaction_log.agent_identity_hash` carries the RFC 7638 JWK Thumbprint

The cross-subsystem link is the `agent_id` string itself:

- `transaction_log.agent_id` (FK to `ramp.agents.agent_id`) names the agent.
- `transaction_log.billing_id` (string, nullable — null for free / subscription paths) names the Billing adapter's reservation handle returned by `Authorize`.
- The TigerBeetle account derivation `sha256("agent:" + agent_id)` is reproducible from `agent_id` alone, no Exchange-DB lookup — the link is by computation, not by table.

**Note — a free request can leave `billing_id` empty or give it a value; both are correct.** A request can be free for two different reasons, and each one stores `billing_id` differently:

- **The content's price is zero** (`unit_cost == 0`). There is nothing to charge, so the Exchange skips the billing step and never calls `Authorize`. `billing_id` stays empty (NULL). This is the case D2 describes.
- **The deployment uses a billing component that never charges.** For example, `billing.FreeAdapter` approves every request but takes no money. Billing still runs as usual: it calls `Authorize`, which returns an id, so `billing_id` holds that id.

So "null for free … paths" above covers only the first reason — a zero price. A `billing_id` that holds a value on free content is expected, not a mistake.

At report time the same distinction runs in reverse. A `UsageReport` against a price-zero transaction (stored `billing_id = NULL`) must carry an **empty** `billing_id`; a non-empty value names a reservation handle that does not exist in this Exchange's transaction log and is rejected (threat model T25 — the Exchange validates the reported `billing_id` exists before accepting). A `FreeAdapter`-served resource carries its ULID handle, which the report must echo exactly, the same as any paid transaction.

No `billing_account_id` column on `ramp.agents`, no separate mapping table, no per-tenant fork of the derivation. An adapter needing richer identity (e.g. Stripe customer ID) keeps that mapping internal to the adapter.

**The `transaction_log.agent_identity_hash` column carries the RFC 7638 JWK Thumbprint.** The column stores the protocol-defined value (proto §1180): the SHA-256 over the canonical JWK form `{"crv":"Ed25519","kty":"OKP","x":"<base64url-nopad(pk)>"}` of the agent's Ed25519 request-signing key at authorization time. This is the same value the Edge embeds in the `agent_id` URL parameter and checks against `thumbprint(presented_key)` (proto §53-65), and the same value ADR-012 §D1 specifies for the Edge delivery log. The reconciler in ADR-011 joins Edge delivery records against `transaction_log` by direct Thumbprint equality — without this swap the join silently mis-matches every row, so the locked value here is what makes ADR-011 implementable.

The previous per-transaction audit fingerprint `sha256(agent_id || "|" || tx_request_id)` is deleted. Both inputs are already verbatim columns on the same row, so the prior hash carries no information the row itself does not already prove; no downstream readers depend on the prior shape.

**Migration shape.** A new migration `000NNN_agent_identity_hash_to_thumbprint.up.sql` adds `agent_identity_thumbprint BYTEA` NULL, backfills via a transient `pgcrypto`-based function computing the RFC 7638 Thumbprint from `ramp.agents.public_key`, tightens to NOT NULL with a 32-byte length check, drops the prior `agent_identity_hash` column, then renames into place. The down migration is mechanical. A known-answer Ed25519 Thumbprint vector test runs before the migration applies.

**Code site.** `src/exchange/internal/service/persist_intent.go` and `src/exchange/internal/service/exchange_batch.go` write the RFC 7638 §3.2 thumbprint to `transaction_log.agent_identity_hash`, using the SDK thumbprint helper rather than a per-transaction `sha256`. The same helper is reusable by the Edge (TS) for `thumbprint(presented_key)`, by the ADR-011 reconciler, and by the Exchange's signing path for the `agent_id` URL parameter.

---

## Out of scope

- **`audit_root` canonicalization scope.** ADR-010 D2 leaves `audit_root` canonicalization to the implementation MR. If it includes `agent_identity_hash`, anchor it to the post-D5 Thumbprint from day one. Flagged for the ADR-010 implementer.
- **On-the-wire encoding of the Thumbprint.** Proto carries `agent_identity_hash` as a string; the website pins base64url-no-pad for the URL parameter; current code uses hex at `marketplace_helpers.go:181`. The encoding decision belongs to the implementer of ADR-010 / ADR-011; pin to base64url-no-pad when those land.
- **Registry-host pull semantics under multi-Exchange load.** Per-Exchange caching policy when a registry hosts manifests for many agents consumed by many Exchanges is operational (CDN at the registry edge handles it cleanly); not a v1 ADR concern.
- **Dispute / refund identity model.** Refunds flow through `DisputeTransaction` (proto §2226-2349) and reuse the same global `agent_id`; the dispute-counter-signature surface (if any) is a future ADR.
- **Cross-Exchange aggregation.** `RevenueReport` (ADR-010) and the reconciler (ADR-011) are per-Exchange in v1. If cross-Exchange aggregation becomes a requirement, the global `agent_id` makes the join natural without protocol change.

---

## Consequences

- The Billing adapter is optional per-transaction; free, subscription-token, and discovery paths never engage it.
- Onboarding has no protocol-level ceremony — a new agent can consume on its first authenticated request.
- Audit and reconciliation are single-key joins; ADR-011's reconciler joins on `agent_identity_hash` (equal on both sides by D5).
- Key rotation is operator-controlled at one URL; the 5-minute TTL bounds global effect; no Billing-side coordination.
- Lazy registration depends on a well-formed discovery anchor — a malformed/unreachable `/.well-known/ramp.json` gets refused. Domainless agents use the registry-host pattern (proto §1664-1670).
- Federated identity is decentralised with bounded staleness; cross-Exchange consistency is bounded by the cache window, not a coordinator.

# RAMP Exchange — Roles and Use-Cases Catalog

**Status**: Living catalog. Updated when new use cases land, when status of an existing one changes, or when a new role is introduced.

**Purpose**: Enumerate the use cases each role of the RAMP Exchange has, plus the implementation status of each ("Today"). ADRs reference IDs from this catalog (e.g. AC-2, PC-1) to scope the surface they make decisions about; this document is the single denormalised place where the surface is named.

**Scope**: This is a *catalog*, not an ADR. It has no decision / consequences / alternatives sections. It describes what the system supports, in what state, and where the next ADR-level work would land. If a use case requires a decision before it can be implemented, the "Pulls on" column points at the relevant (sometimes still-forthcoming) ADR.

**Status legend**:

- `✓ implemented` — wired end-to-end, has integration coverage.
- `partial` — some surface exists (e.g. a DB column, a manual code path) but the role-facing flow is incomplete.
- `✗ not yet` — no production code path exists.
- `n/a` — out of scope for the current phase.

---

## Roles

The Exchange recognises four primary roles. The fifth — *Broker* — is not a role on the Exchange's surface; it is an intermediary that consumes the Agent surface on behalf of agents. See ADR-006 for the Broker model.

- **Agent** — consumes content. Authenticated via Ed25519 keys served from the Web Bot Auth directory at `/.well-known/http-message-signatures-directory` on the agent's domain (RAMP-native self-signup, no admin onboarding required).
- **Publisher** — the business that owns specific content. Authenticated via Ed25519 keys served from the Web Bot Auth directory on the publisher's domain. A publisher is *who gets paid* on `RevenueReport`; it is distinct from Tenant (below).
- **Exchange admin** — operator of the Exchange instance. Today there is **no admin HTTP surface** (see `transport/admin_removed_e2e_test.go`): admin actions are SQL against the database or future tooling.
- **Edge / delivery node** — the entity that serves bytes to the agent. Verifies signed URLs at request time. Today the Edge is a thin TS worker (`src/edge/`); the audit-grade "third witness" delivery log does not exist.

**Tenant vs Publisher.** A **Tenant** is the operational entity inside the Exchange — a "deployment slot" carrying per-tenant signing keys, fee rate (`fee_rate_bps`), reporting policy, signed-URL scheme, and catalog. One Exchange instance can serve many tenants. A **Publisher** is the business that owns specific content; one tenant can host content for one or more publishers (the SaaS shape — N publishers per tenant — is live from day one in our deployment plan, not a v2 abstraction). `tenant_id` on requests routes operationally; `publisher_id` on `RevenueReport` identifies the payee. The two concepts are deliberately separate even when the operator's first deployment has one publisher per tenant; do not collapse them.

---

## Agent (AC-*)

| # | Use case | Today | Pulls on |
|---|---|---|---|
| AC-1 | Discover available content | ✓ `ramp.v1.ExchangeService/DiscoverResources` | — |
| AC-2 | Accept an offer and receive a signed URL | ✓ `ExecuteTransaction` → Authorize → URL mint (Ed25519 or RSA CloudFront per tenant) | ADR-009 |
| AC-3 | Fetch content from the Edge using the URL | ✓ Edge serves; URL signature verified via `@ramp-protocol/sdk-l1/verify` | ADR-012 |
| AC-4 | Report usage of the content | ✓ `ReportUsage` (pure audit endpoint, post-MR-2; no money movement) | ADR-009 |
| AC-5 | Dispute a transaction | ✗ `DisputeTransaction` not implemented | ADR-011 |
| AC-6 | View own balance, quota, transaction history | ✗ no admin / self-service surface (billing adapter exposes `GetBalance` but it is not wired to any RPC) | ADR-010 (admin UI / self-service plane) |
| AC-7 | Top up balance / fund the account | partial — a newly registered agent receives the tenant-configured one-time default credit at Register (`tenants.default_agent_credit`, 0 = disabled; ADR-009 amendment 2026-08-13); ongoing top-up stays out-of-protocol (operator funding scripts / billing-provider action) | ADR-010 |
| AC-8 | Maintain own identity (well-known documents, key rotation) | partial — self-signup against the agent's own key directory is implemented (`agent_self_signup_e2e_test.go`); key rotation is TBD | ADR-009 |
| AC-9 | Receive a refund (passive) | ✗ no Refund adapter method yet (incoming via the refund follow-up) | ADR-011 (output side) |

---

## Publisher (PC-*)

| # | Use case | Today | Pulls on |
|---|---|---|---|
| PC-1 | Publish offers (push catalog) | ✓ `ramp.v1.CatalogService/PushResources` with RFC 9421 httpsig (`publisher_onboarding_e2e_test.go`) | — |
| PC-2 | Configure pricing, tolerance, required fields, reporting window | ✓ `tenants.reporting_policy` JSONB drives `reporting_obligations.required_fields` / `quantity_tolerance` (migration 000008) | — |
| PC-3 | Receive payouts | ✗ not designed | ADR-010 |
| PC-4 | View revenue accrual per period | ✗ no admin / self-service surface | ADR-010 |
| PC-5 | View transaction history per offer | ✗ no admin / self-service surface | ADR-010 |
| PC-6 | Respond to disputes (acknowledge / contest) | ✗ not designed | ADR-011 |
| PC-7 | Maintain own identity (offer-signing keys) | partial — offer signing is implemented (`signing.OfferSigner`); explicit key rotation flow is TBD | ADR-009 |
| PC-8 | Configure delivery (which Edge serves what `content_hash`) | ✗ not designed | ADR-012 |

---

## Exchange admin (EC-*)

| # | Use case | Today | Pulls on |
|---|---|---|---|
| EC-1 | Onboard a tenant (publisher) | partial — `ramp.tenants` rows can be inserted manually; no admin RPC. Lazy publisher self-signup at `PushResources` time covers the happy path | ADR-009 |
| EC-2 | Onboard an agent (verify domain → public key chain) | partial — `agentreg.Registry` exists with lazy key-directory resolution; explicit operator-driven ceremony is TBD | ADR-009 |
| EC-3 | View transactions across tenants | ✗ no admin surface (DB rows queryable via SQL; nothing role-facing) | ADR-010 |
| EC-4 | Manually credit / debit an agent balance | partial — no admin surface for arbitrary per-agent credit/debit (operator funding scripts remain the tool); the tenant-wide default credit for new agents is deployment configuration (`EXCHANGE_DEFAULT_AGENT_CREDIT` is the sole channel: each boot replaces `tenants.default_agent_credit` with it, unset means 0 — no admin RPC and no operator-SQL channel) | ADR-010 |
| EC-5 | Investigate a dispute (review the three signed sources: offer, transaction, delivery) | ✗ no admin surface; the third witness (signed delivery log) does not exist | ADR-011 + ADR-012 |
| EC-6 | Trigger / monitor reconciliation runs | ✗ not designed | ADR-011 |
| EC-7 | View FX position / treasury (Phase 3 only) | n/a | future |
| EC-8 | System health (revenue, error rates, latency) | partial — structured logs (`slog`) exist on all three services; no dashboard | (ops) |

---

## Edge / delivery node (EDC-*)

| # | Use case | Today | Pulls on |
|---|---|---|---|
| EDC-1 | Verify signed URL on incoming fetch | ✓ Ed25519 verification implemented via `@ramp-protocol/sdk-l1/verify`; RSA CloudFront signed URLs verified natively by CloudFront | — |
| EDC-2 | Serve content when URL valid | ✓ basic origin-proxy serve path (`src/edge/src/app.ts`) | — |
| EDC-3 | Sign and log delivery record (the third witness) | ✗ this is the gap — Edge currently neither signs nor records deliveries | ADR-012 |
| EDC-4 | Publish delivery logs to a queryable store | ✗ not designed | ADR-012 |
| EDC-5 | Verify `content_hash` on outbound bytes | ✗ depends on whether the offer signs the `content_hash` over the served object | ADR-012 |

---

## Cross-references

- **ADR-001 .. ADR-008** — existing ADRs in this directory. ADR-006 (Broker intermediation) is the primary upstream for the Agent surface.
- **ADR-009 (forthcoming)** — identity & key lifecycle (agent + publisher onboarding, key rotation). Pulls on AC-2, AC-4, AC-8, PC-7, EC-1, EC-2.
- **ADR-010 (forthcoming)** — admin / self-service surface (balance, history, payouts). Pulls on AC-6, AC-7, PC-3, PC-4, PC-5, EC-3, EC-4.
- **ADR-011 (forthcoming)** — dispute & refund flow. Pulls on AC-5, AC-9, PC-6, EC-5, EC-6.
- **ADR-012 (forthcoming)** — Edge delivery record (the third signed witness). Pulls on AC-3, PC-8, EC-5, EDC-3, EDC-4, EDC-5.

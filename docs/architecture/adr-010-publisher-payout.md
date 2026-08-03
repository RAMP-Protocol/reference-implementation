# ADR-010 — Publisher Payout: Accrual, Reporting, and the Future Adapter

**Status:** Accepted (2026-06-02); **amended 2026-06-29** — the payee is the **resource owner**, not the tenant; `resource_owner_id` is an owner-attested identity sourced from the owner manifest (carried on `AuthorizedExchange`), and the commission rate moves from a single `ramp.tenants` column to a `(tenant, resource_owner)` registry with a tenant-level fallback, resolved at **Authorize** and carried on the hold. See the [Amendment (2026-06-29)](#amendment-2026-06-29--resource-owner-identity--commission-registry) section. Implemented under the TigerBeetle billing work.

---

## Context

The Exchange settles agent charges through `billing.Adapter`. The lifecycle is `Authorize` → mint signed URL → commit WAL → `Record` (best-effort, post-commit), with `Release` and `Refund` for the abort paths. Under the persisted ledger (TigerBeetle), `Record`'s credit side lands in a `publisher:revenue:{ledger}` account per `(publisher_id, currency_ledger)`. That balance is accrued revenue. Nothing turns it into money in the publisher's bank.

Three constraints shape what follows: the publisher's daily-dashboard number must equal what they will eventually be paid; the hot path is thousands-of-TPS agentic access, so synchronous external transfer calls are off the table; and operators need their choice of payout rail for the same reasons they need their choice of billing rail.

v1 ships a reporting-only surface; v2 adds a `PayoutAdapter` sibling to the billing adapter.

---

## Decision

### D1 — Per-transaction fee split at `Record` time

Every `Record` that settles a charge produces two atomic credit postings on the same ledger:

1. `publisher:revenue:{ledger}` — `unit_cost × quantity − platform_fee`.
2. `platform:fee:{ledger}` — the platform's cut.

The per-tenant fee rate is resolved at `Record` time and the resolved amount is what the ledger stores. Later rate changes do not move historical postings; the refund path (D4) reverses the *posted* amount, never the *current* rate.

Splitting here, not at payout time, makes the publisher's accrued balance the literal predicate the payout settles against — the daily view and the bank deposit derive from the same number. Two postings rather than one publisher posting plus a tracked-fee field keeps the platform's own revenue auditable on the same ledger surface as the publisher's.

The fee rate is a single mutable `fee_rate_bps INTEGER NOT NULL CHECK (fee_rate_bps >= 0 AND fee_rate_bps < 10000)` column on `ramp.tenants`, plus a `fee_rate_notes TEXT` column for operator commentary. Basis points avoid float drift. Rate changes are rare at v1 scale (1–3 customers); historical rates are recoverable from the ledger because every `Record` posts the amount that was in force.

### D2 — v1 ships only `RevenueReport`; payout is reporting, not money movement

The v1 Exchange exposes one new RPC:

```
rpc GetRevenueReport(RevenueReportRequest) returns (RevenueReportResponse);
```

`RevenueReportRequest`: `tenant_id`, `publisher_id`, `period_start` / `period_end` (inclusive-exclusive UTC, no fixed calendar imposed), `currency` (ISO 4217, maps to a TigerBeetle ledger ID), `include_transactions` (default false to keep daily-dashboard calls cheap).

`RevenueReportResponse`: echoed `period_start` / `period_end` / `currency`; `gross_revenue`; `platform_fee`; `net_revenue = gross_revenue − platform_fee`; `refunded_amount` and `refunded_platform_fee` (proportional reversals per D4); `net_payable = net_revenue − (refunded_amount − refunded_platform_fee)`; `transaction_count` / `refund_count`; an `audit_root` SHA-256 over the canonical concatenation of contributing transaction IDs and postings (byte-identical across repeat calls for the same window, so a publisher can verify offline against the Exchange's signed transaction log); repeated `transactions` rows when requested; an `absence_reason` enum (`UNSPECIFIED`, `NO_TRANSACTIONS_IN_PERIOD`, `UNKNOWN_PUBLISHER`, `UNSUPPORTED_CURRENCY`, `INTERNAL_ERROR`) — ADR-008 D2 requires empty responses to set one.

The RPC aggregates directly against TigerBeetle on every call. At v1 scale, reports complete in milliseconds; no cache, no materialised view.

**No money moves.** The RPC reads the ledger and signs the report. Settlement runs off-platform on whatever channel the operator and publisher have agreed (invoice, ACH, wire, standing order). The Exchange's job ends at producing a report whose `audit_root` makes it verifiable. Cadence of consultation vs. cadence of payment is a contractual matter the Exchange is indifferent to.

### D3 — v2 adds a `PayoutAdapter` interface, sibling to `BillingAdapter`

The extension path is a new adapter and wiring point, not a change to the RPC above:

```go
package payout

type Request struct {
    TenantID       string
    PublisherID    string
    Amount         Amount
    Currency       string
    PeriodStart    time.Time
    PeriodEnd      time.Time
    AuditRoot      []byte
    IdempotencyKey string  // e.g. "payout:{publisher_id}:{period_start}:{period_end}"
}

type Result struct {
    PayoutID string
    Approved bool
    Reason   string
}

type Adapter interface {
    Pay(ctx context.Context, req Request) (Result, error)
    GetStatus(ctx context.Context, payoutID string) (Status, error)
}
```

`Pay` is idempotent on `IdempotencyKey`; `GetStatus` is the reconciliation path. `BillingAdapter` moves money from agents into the publisher revenue account; `PayoutAdapter` moves it from that account to an external destination.

Concrete v2 implementations, in rough order of operator demand: `StripeConnectAdapter` (`Transfer.create` against a connected account; viable for monthly-payout use cases that need not traverse the hot path), `BankACHAdapter` (NACHA file generation against the operator's bank API), `OnChainTransferAdapter` (same-rail when `publisher:revenue:{ledger}` is a stablecoin balance), `NoopPayoutAdapter` (returns approval and posts a `payout:settled:{ledger}` entry for operators paying manually).

The interface mirrors `BillingAdapter` because operators want choice of rail. Shipping the report first and the adapter second is deliberate: every payout reconciliation cycle starts with "show me what is owed."

**Security obligation on the payout path (binding for the v2 adapter).** `resource_owner_id` is a **self-attested, global payee namespace**: a domain directs *its own* revenue to an account by attesting the id in its manifest, which is safe only because the payout *destination* lives in the server-side registry, not the manifest (Amendment A — "self-attestation is safe"). A future `PayoutAdapter` or withdrawal RPC therefore MUST authenticate the party requesting a payout against the **same domain root of trust** that attested the `resource_owner_id` (the owner manifest / `/.well-known` key) before releasing funds. Skipping that check turns the self-attested namespace into a drain vector — anyone who could name an owner id could withdraw its accrued revenue. The v1 reporting surface (D2) is read-only and moves no money, so this binds v2; it is recorded here so the payout adapter cannot ship without it.

### D4 — Refund proportionally reverses both postings

`Refund(billingID, amount, reason, idempotencyKey)` reverses **both** the publisher revenue posting and the platform fee posting, proportionally to the refund's share of the original gross. The reversal uses the fee amount posted at the original `Record`, never the current `tenants.fee_rate_bps`. This is what lets the rate column be mutable: historical postings carry their own truth.

Given an original transaction with `gross = unit_cost × quantity`, `fee_posted` recorded on `platform:fee:{ledger}`, and `net_posted = gross − fee_posted`, a partial refund `R` (where `0 < R ≤ gross`) produces:

```
refund_share = R / gross
fee_reversal = fee_posted × refund_share
net_reversal = R − fee_reversal
```

Postings: credit `agent:{agent_id}:{ledger}` with `R`; debit `publisher:revenue:{ledger}` with `net_reversal`; debit `platform:fee:{ledger}` with `fee_reversal`.

Worked example, `$1.00` transaction at `10%` fee:

| Step | Action | Agent balance | Publisher revenue | Platform fee |
|---|---|---|---|---|
| 1 | `Record` (full settle) | −100 | +90 | +10 |
| 2 | `Refund(amount = $0.30)` | +30 | −27 | −3 |
| | **Net after refund** | **−70** | **+63** | **+7** |

Agent paid 70¢; publisher kept 63¢; platform kept 7¢. The 7/70 = 10% fee rate is preserved through the partial refund.

The alternatives both fail. "Publisher absorbs the full refund" lets the platform keep fees on a transaction it has agreed was not legitimately settled. "Platform absorbs the full refund" leaves the publisher with `$0.90` on a fully-refunded transaction at the platform's expense. That second model can be a contractual tier; it is not the default.

`IdempotencyKey` keys both reversals together — a second `Refund` with the same key is a no-op against both accounts. TigerBeetle's linked transfers satisfy this natively; other adapters must emulate. Refunding more than the original gross returns `ErrRefundExceedsRecord` and leaves postings untouched. Cumulative refunds against the same `billingID` apply the same proportional split against the same original gross.

### D5 — Single currency for v1; multi-currency mechanic exists but is deferred

v1 operates in one currency per deployment (configured per deployment; the ledger-per-currency model is deferred). `publisher:revenue:{ledger}` and `platform:fee:{ledger}` are scoped to that ledger ID. Requests for any other currency return `absence_reason = UNSUPPORTED_CURRENCY`.

The TigerBeetle model already supports ledger-per-currency and atomic cross-currency transfers without rebuilding. What is deferred is the operational layer: treasury funding per currency, FX rate sourcing, hedging policy, per-publisher currency election. That deferral holds here.

---

## Out of scope

Deliberate v1 omissions, each additive:

- **Bitemporal `tenant_fee_rate` table.** Defer until a customer asks for rate-change history. Seed the existing row, switch the lookup to consult the table by transaction timestamp, demote the column to a current-rate cache.
- **`MATERIALIZED VIEW revenue_report_daily` + `as_of_timestamp` field.** Defer until a report exceeds ~1s of compute. Refresh at T+1, add the response fields.
- **Operator UI for scheduled future rate changes.** Admin tools, not the Exchange.
- **`PayoutAdapter` implementations.** v2 work, per D3.
- **Multi-currency operations** (treasury, FX, per-publisher election). Deferred; see D5.
- **Tax / VAT / withholding compliance.** Operator runbooks and onboarding contracts.
- **Operator UI for revenue dashboards.** Admin tools; consumes `RevenueReport` like any other client.
- **Canonical encoding of `audit_root`.** Pinned in the implementation MR's design doc; this ADR commits to the property (byte-identical roots from identical windows), not the algorithm.

---

## Consequences

**Positive.** The daily-dashboard number, the monthly statement, and the bank deposit all derive from the same `publisher:revenue:{ledger}` postings. Refund symmetry is correct by construction. The v1 surface is one read-only RPC — no new write paths, no background workers. `PayoutAdapter` is wiring a sibling port, not changing the core. `audit_root` lets a publisher's accountant verify the report against the same signed objects the agents received.

**Negative.** Two postings per transaction — handled by TigerBeetle's linked-transfer pair, negligible at design throughput but not free. Direct ledger aggregation does not scale forever; beyond v1 customer counts the materialised-view upgrade becomes the work item. The `audit_root` canonicalisation binds the implementation to one algorithm. v1 has no automatic payment — operators wanting programmatic payout wait for v2.

**Rejected alternatives.** Fee split at payout time (publisher sees gross daily, net monthly, discovers the gap). Stripe Connect splits at `Record` (100–500ms HTTP call on every `ExecuteTransaction`; Stripe Connect is the v2 adapter, not the v1 default). Embedding payout cadence in the protocol (overconstrains operators who pay weekly, quarterly, or on demand). Refund-keep-the-fee. Refund-platform-eats-the-fee (acceptable as a tier, not the default). Single combined publisher transfer with platform fee in a sidecar table (asymmetric, makes platform revenue second-class on the ledger). Refund consulting the current `tenants.fee_rate_bps` (re-introduces "platform keeps fees on disputed transactions" across rate-change boundaries).

---

## Amendment (2026-06-29) — resource-owner identity + commission registry

**Status of this amendment:** Accepted (2026-06-29). Implemented under the TigerBeetle
billing work. The proto and code changes follow
separately. This amendment resolves two questions that surfaced on starting the TigerBeetle billing work:
*who the revenue posting is keyed to* and *where the commission rate lives* — and
reconciles this ADR's "publisher" wording with the `resource_owner` terminology the
rest of the architecture already uses (ADR-002 — "Publisher appears only in demo
examples"; the ADR-001 key-hosting amendment — `/.well-known/ramp-keys` hosted on each
resource owner).

The original Decision text above is preserved as the record. Where it conflicts with
this amendment, **this amendment governs**. The deltas, by decision:

### A — The payee is the resource owner (`resource_owner_id`), keyed distinctly from the tenant

The accrued-revenue account is keyed by a **`resource_owner_id`**, not by the tenant
and not by the content domain. Two identities are pinned and **deliberately separate**
(`roles-and-use-cases.md:27` — "do not collapse them"):

- **`tenant_id`** — the operational slot: who pushed, which deployment. Derived from
  the content domain as today; routes operationally.
- **`resource_owner_id`** — the payee: **owner-attested**, shared across all of one
  owner's domains, so an owner that monetises many domains is paid as **one** entity
  and an aggregator keeps the owners it represents distinct.

**Source.** `resource_owner_id` is declared by the owner on **`AuthorizedExchange`**
(the `exchanges[]` entry of their `ramp.json`). Every domain an owner controls declares
the **same** value in its entry for this Exchange; that shared value is the grouping.
Until the typed proto field ships it rides in the existing
`AuthorizedExchange.ext` struct as **`ext.resource_owner_id`** (the `ext` field already
exists on the message), so this work is not blocked on a protocol release; promote to
the typed field in the next proto cut.

**Flow on existing machinery.** The Exchange already fetches the owner manifest at
catalog push (contributor-authorisation). The same fetch reads `resource_owner_id` from
the `AuthorizedExchange` entry matching this Exchange and stores it on the **catalog
entry** (new `ramp.catalog.resource_owner_id` column). At settlement the transaction
resolves to its catalog entry, which carries `resource_owner_id`; the ledger keys the
revenue posting by it.

**Self-attestation is safe.** A domain can only direct **its own** revenue to an
account; it cannot redirect another account's payouts (the payout destination lives in
the server-side registry, not the manifest). The worst a misconfigured or hostile
domain can do is donate its own revenue away — not steal someone else's.

**Attestation is required.** Attestation is the *grouping* mechanism — an owner declares
the same `resource_owner_id` across the domains it wants paid as one entity. Because the
payee must never be inferred, a manifest that omits `resource_owner_id` **cannot sell**:
the Exchange **rejects** such an entry at catalog push (it never enters the catalog, so
no offer and no settlement can exist for it), reusing the existing per-entry catalog-push
rejection path. There is deliberately **no fallback to `tenant_id`** — the tenant is the
operational slot (an opaque `t_<uuid>`, distinct from `domain`), not a payee; inferring it
would re-introduce the publisher/tenant collapse this amendment exists to prevent. The fee
rate's tenant-level fallback in §B is a *rate* default, not an identity default — the two
are intentionally asymmetric. **Consequence:** every catalog push must attest
`resource_owner_id`, including free/demo tiers and the first-deployment manifests; a
warn-now / enforce-later phase-in is the implementer's option if a hard gate would block
that deployment before its manifest is updated.

**Account naming.** The revenue account named `publisher:revenue:{ledger}` in D1/D4
above is, under this amendment, **`owner:revenue:{resource_owner_id}:{ledger}`** —
the same account, keyed and named by the resource owner. The platform account stays
`platform:fee:{ledger}`. This aligns the ledger surface with the `resource_owner`
vocabulary; reporting (D2, the future RevenueReport surface) reads the same account.
The `{ledger}` segment is the **multi-currency form deferred to D5**: Phase-1 code is
single-currency and keys the account id by the 3-part `owner:revenue:{resource_owner_id}`
only (the ledger/currency is deliberately not folded into the id — see the account-id
derivation), so a single deployment currency needs no `{ledger}` suffix. Fold `{ledger}`
in when multi-currency lands.

### B — Commission lives on a `(tenant, resource_owner)` registry, resolved at Authorize

This **amends D1's** "single mutable `fee_rate_bps` column on `ramp.tenants`" and D1's
"resolved at `Record` time":

- **Where.** The rate is a `(tenant, resource_owner)` registry row, with a
  **tenant-level rate as the default/fallback**. The `ramp.tenants.fee_rate_bps`
  (+ `fee_rate_notes`) column from D1 is retained **as that tenant-level default**; a
  per-`(tenant, resource_owner)` override row supplies a different rate where present.
  This lets an aggregator tenant charge a different commission per owner it represents.
  Commission is **never on the wire** — it is a server-side commercial term.
- **Basis points** semantics are unchanged from D1: integer `bps`, `1 bp = 0.01%`,
  `fee = gross × bps / 10000`, constrained `0 ≤ bps < 10000`.
- **When.** The effective rate is **resolved at Authorize** (the tenant — hence the
  rate — is already loaded there) and **carried on the billing hold** next to the
  already-frozen gross; the fee amount is computed and posted at **Record**. This moves
  the freeze point from Record (D1's wording) to Authorize so that **both halves of the
  split are frozen at the same instant**, and it keeps the billing adapter **free of any
  database access** with the **`Record()` signature unchanged** (the rate rides as an
  additive field on the authorize request). The D1/D4 invariant is preserved: the
  **posted** amount is the truth, so the rate columns stay freely mutable without
  rewriting history; D4's reversal reads the posted fee, "never the current rate" — now
  "never the current `(tenant, resource_owner)` rate."

### C — Rounding rule pinned (refines D1 and the D4 reversal)

`fee = floor(gross × bps / 10000)`; the **platform absorbs the sub-cent remainder**
(`net = gross − fee`). The **same floor rule** applies on the proportional refund:
`fee_reversal = floor(fee_posted × R / gross)`, `net_reversal = R − fee_reversal`. This
keeps the split exact across settle and refund and maps directly onto TigerBeetle's
integer minor-unit amounts. The D4 worked example (`$1.00 @ 10%`, refund `$0.30` →
agent −70, owner +63, platform +7) is unchanged and is a required test vector.

### What this amendment does NOT change

- **The two-posting split principle** (D1): one revenue posting `(gross − fee)` to the
  owner, one `fee` posting to the platform, atomic. Only the payee key, the rate's home,
  the freeze point, and the rounding rule are pinned.
- **Refund symmetry and proportionality** (D4): unchanged except the fee source (the
  registry) and the pinned rounding.
- **Reporting-only v1 / no money moves** (D2), the **`PayoutAdapter` v2 extension**
  (D3), and **single-currency v1** (D5) all stand. D2's `RevenueReportRequest.publisher_id`
  is, semantically, the `resource_owner_id`; the report aggregates by resource owner
  against the `owner:revenue:{…}` accounts.

### Out of scope of this amendment (noted to bound it)

- The **`authoritative_location`** manifest pointer (an AdCP-style scaling mechanism so
  an owner with thousands of domains maintains one authoritative manifest) — that is
  manifest resolution / discovery, not payout; a sibling concern.
- The **typed** proto `resource_owner_id` field (this amendment uses `ext`).
- The broader resource-owner **registry** beyond the rate slice (payout destination,
  KYC, etc.) — the rate is what billing needs now; the rest is v2 (D3).

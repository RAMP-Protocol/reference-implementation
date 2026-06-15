# ADR-010 — Publisher Payout: Accrual, Reporting, and the Future Adapter

**Status:** Accepted (2026-06-02)

---

## Context

The Exchange settles agent charges through `billing.Adapter`. The lifecycle is `Authorize` → mint signed URL → commit WAL → `Record` (best-effort, post-commit), with `Release` and `Refund` for the abort paths. Under the persisted ledger (RAMP-3 / TigerBeetle), `Record`'s credit side lands in a `publisher:revenue:{ledger}` account per `(publisher_id, currency_ledger)`. That balance is accrued revenue. Nothing turns it into money in the publisher's bank.

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

v1 operates in one currency per deployment (configured per RAMP-3 §"Currency configuration model"). `publisher:revenue:{ledger}` and `platform:fee:{ledger}` are scoped to that ledger ID. Requests for any other currency return `absence_reason = UNSUPPORTED_CURRENCY`.

The TigerBeetle model already supports ledger-per-currency and atomic cross-currency transfers per RAMP-3 §"Multi-currency without rebuilding". What is deferred is the operational layer: treasury funding per currency, FX rate sourcing, hedging policy, per-publisher currency election. The deferral comes from RAMP-3 and holds here.

---

## Out of scope

Deliberate v1 omissions, each additive:

- **Bitemporal `tenant_fee_rate` table.** Defer until a customer asks for rate-change history. Seed the existing row, switch the lookup to consult the table by transaction timestamp, demote the column to a current-rate cache.
- **`MATERIALIZED VIEW revenue_report_daily` + `as_of_timestamp` field.** Defer until a report exceeds ~1s of compute. Refresh at T+1, add the response fields.
- **Operator UI for scheduled future rate changes.** Admin tools, not the Exchange.
- **`PayoutAdapter` implementations.** v2 work, per D3.
- **Multi-currency operations** (treasury, FX, per-publisher election). Per RAMP-3 and D5.
- **Tax / VAT / withholding compliance.** Operator runbooks and onboarding contracts.
- **Operator UI for revenue dashboards.** Admin tools; consumes `RevenueReport` like any other client.
- **Canonical encoding of `audit_root`.** Pinned in the implementation MR's design doc; this ADR commits to the property (byte-identical roots from identical windows), not the algorithm.

---

## Consequences

**Positive.** The daily-dashboard number, the monthly statement, and the bank deposit all derive from the same `publisher:revenue:{ledger}` postings. Refund symmetry is correct by construction. The v1 surface is one read-only RPC — no new write paths, no background workers. `PayoutAdapter` is wiring a sibling port, not changing the core. `audit_root` lets a publisher's accountant verify the report against the same signed objects the agents received.

**Negative.** Two postings per transaction — handled by TigerBeetle's linked-transfer pair, negligible at design throughput but not free. Direct ledger aggregation does not scale forever; beyond v1 customer counts the materialised-view upgrade becomes the work item. The `audit_root` canonicalisation binds the implementation to one algorithm. v1 has no automatic payment — operators wanting programmatic payout wait for v2.

**Rejected alternatives.** Fee split at payout time (publisher sees gross daily, net monthly, discovers the gap). Stripe Connect splits at `Record` (100–500ms HTTP call on every `ExecuteTransaction`; Stripe Connect is the v2 adapter, not the v1 default). Embedding payout cadence in the protocol (overconstrains operators who pay weekly, quarterly, or on demand). Refund-keep-the-fee. Refund-platform-eats-the-fee (acceptable as a tier, not the default). Single combined publisher transfer with platform fee in a sidecar table (asymmetric, makes platform revenue second-class on the ledger). Refund consulting the current `tenants.fee_rate_bps` (re-introduces "platform keeps fees on disputed transactions" across rate-change boundaries).

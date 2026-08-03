// Package billing abstracts the money movement for Exchange transactions.
//
// Protocol sequence for ExecuteTransaction:
//
//  1. Authorize  — MAY reserve funds against the estimated quantity.
//  2. Signed URL — minted after Authorize succeeds.
//  3. WAL write  — transaction row committed to the DB.
//  4. Record     — confirms the transaction in the billing system, called
//     synchronously at the end of ExecuteTransaction with the
//     estimated quantity. Best-effort: failure is logged and
//     the transaction stays committed.
//
// Release is called only when ExecuteTransaction fails AFTER Authorize but
// BEFORE completion (URL signing failed, persist failed). Never called on the
// success path. Never called by ReportUsage.
//
// Refund reverses a settled charge (post-Record). It has no caller in v1 —
// the dispute path (proto §2226-2349) is deferred — but it completes the
// adapter contract so the persisted-ledger adapter (TigerBeetle) does not have
// to reshape the interface. Internals are adapter-specific: a ledger reverses
// the capture, a metered adapter books a forward credit, a demo adapter has no
// charge to reverse and reports ErrRefundUnsupported.
//
// ReportUsage is a pure audit endpoint and does not move money. Estimated vs
// actual quantity reconciliation is the adapter implementation's concern.
//
// Idempotency. Every state-changing method takes a caller-supplied
// idempotencyKey (Authorize via AuthorizeRequest.IdempotencyKey). The key is
// opt-in: an empty key disables dedup and the call always executes. A persisted
// adapter MAY instead REQUIRE a non-empty key and soft-deny an empty one
// (Approved=false): a deterministic-id ledger cannot execute a keyless hold
// without collapsing every hold to one shared id, so it refuses rather than risk
// a cross-settle. The RPC boundary supplies a non-empty key on every call. With a
// non-empty key:
//   - Authorize dedups on (billing_ref, key) WHILE the resulting hold is live —
//     a repeat returns the same BillingID without a second reservation. Record
//     or Release of that hold FREES the key, so a later Authorize with the same
//     key mints a fresh BillingID. (Freeing on resolve is load-bearing: a hold
//     voided by Release must not be handed back to a retry, or the subsequent
//     Record settles nothing and the agent is never charged.)
//   - Record / Release / Refund are idempotent on (billingID, op, key): a
//     replay with the same key is a no-op success. Distinct ops do not collide.
package billing

import (
	"context"
	"errors"
	"fmt"
	"math/big"
)

// Amount is the currency-normalized value transferred in a single operation.
// Stored as big.Rat to avoid float rounding when aggregating balances.
type Amount struct {
	Value    *big.Rat
	Currency string
}

// NewAmount parses a decimal string (e.g. "0.05") into an Amount.
func NewAmount(raw, currency string) (Amount, error) {
	r := new(big.Rat)
	if _, ok := r.SetString(raw); !ok {
		return Amount{}, fmt.Errorf("billing: cannot parse amount %q", raw)
	}
	return Amount{Value: r, Currency: currency}, nil
}

// totalCharge is the gross charge for a line item — unit cost × quantity, in the
// unit cost's currency. Shared by the adapters so the "gross = unit × qty" rule is
// expressed once.
func totalCharge(unitCost Amount, quantity int64) Amount {
	return Amount{
		Value:    new(big.Rat).Mul(unitCost.Value, new(big.Rat).SetInt64(quantity)),
		Currency: unitCost.Currency,
	}
}

// AuthorizeRequest captures what the Exchange needs billing to evaluate.
type AuthorizeRequest struct {
	TenantID string
	// BillingRef is the paying account handle minted by Register and stored on
	// the agent's ramp.agents row (ADR-021). It is NEVER the caller's wire
	// label: the service reads it from the row keyed by the verified signature
	// identity, so a caller cannot pick which account it charges. An empty ref
	// means the agent never registered and cannot buy paid content.
	BillingRef string
	UnitCost   Amount
	Quantity   int64  // unit count from the Offer (e.g. estimated_quantity)
	Unit       string // e.g. "tokens", "pages"
	// IdempotencyKey is the Exchange-supplied dedup anchor (= tx_request.id).
	// Empty disables Authorize dedup. See the package idempotency contract.
	IdempotencyKey string
	// ResourceOwnerID is the owner-attested payee the settlement revenue is
	// keyed to, and FeeRateBps is the platform commission in basis points
	// resolved at Authorize. Both are frozen on the hold here so a settling
	// adapter posts the revenue/fee split from one transaction's truth without
	// any database read. Non-splitting adapters (free, in-memory) ignore them.
	// Server-side commercial terms, never on the wire.
	ResourceOwnerID string
	FeeRateBps      int
}

// AuthorizeResult carries the post-authorize state back to the service.
type AuthorizeResult struct {
	BillingID string
	Approved  bool
	Reason    string // populated when Approved is false
}

// Adapter is the narrow interface exchange.ExchangeService depends on.
//
// Atomicity stance: the service treats every adapter call as a single atomic
// operation. The service does NOT retry adapter calls and does NOT split a
// logical action across multiple calls. Idempotency is the adapter
// implementation's responsibility, keyed as described in the package doc.
type Adapter interface {
	// EnsureAgentAccount creates the agent's ledger account for a freshly
	// registered billing_ref; called by the Exchange's Register flow
	// (ADR-021 D5). Safe to call again: an account that already exists is
	// success, not an error, and its balance is untouched. An empty
	// billingRef is rejected — the Exchange generates the ref before
	// calling, so an empty value is a caller bug, not a business denial.
	EnsureAgentAccount(ctx context.Context, billingRef string) error
	// Authorize reserves funds against the estimated quantity. Returns a
	// BillingID that identifies the reservation for subsequent Record/Release
	// calls. The reservation MAY hold balance (prepaid model) or simply
	// validate eligibility (metered model). Balance is not settled until
	// Record runs. Idempotent on (billing_ref, IdempotencyKey) while the hold is
	// live (see package doc).
	Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResult, error)
	// Record confirms the transaction in the billing system. Called
	// synchronously at the end of ExecuteTransaction, post-WAL, post-sign.
	// Best-effort: the caller logs but does not fail the request on Record
	// errors. The settled charge is the amount Authorize reserved; the
	// advisoryQuantity argument is advisory (a metered adapter MAY use it to
	// submit a delta meter event, but MUST NOT recompute the settled charge
	// from it). Idempotent on (billingID, idempotencyKey).
	Record(ctx context.Context, billingID string, advisoryQuantity int64, idempotencyKey string) error
	// Release cancels a previously authorized hold without recording any
	// consumption. Called when ExecuteTransaction fails AFTER Authorize but
	// BEFORE completion (URL signing failed, persist failed). Never called on
	// the success path, never called by ReportUsage. A second call for an
	// already-released or already-recorded billingID MUST return
	// ErrUnknownBillingID, which callers treat as a successful no-op. A replay
	// with the same idempotencyKey is a no-op success.
	Release(ctx context.Context, billingID string, idempotencyKey string) error
	// Refund reverses a previously recorded settlement, in part or full.
	// Called from the dispute path (deferred in v1); never called on the
	// success path, by ReportUsage, or by ExecuteTransaction. Idempotent on
	// (billingID, idempotencyKey). amount MUST be positive and MUST NOT exceed
	// the recorded charge net of prior refunds (ErrRefundExceedsRecord).
	// Refunding a held-but-not-recorded billingID returns ErrRefundBeforeRecord;
	// an unknown billingID returns ErrUnknownBillingID. Adapters with no
	// post-capture reversal primitive return ErrRefundUnsupported.
	//
	// Authorization: callers MUST verify the requesting party is authorised to
	// dispute this transaction (typically the original paying agent, or an
	// operator with admin scope) BEFORE invoking Refund. The adapter performs
	// no authorisation check. The reason string is a free-text dispute memo
	// (ADR-011 D7 inverse-posting memo); adapters that keep a ledger persist it
	// for the audit trail.
	Refund(ctx context.Context, billingID string, amount Amount, reason string, idempotencyKey string) error
	GetBalance(ctx context.Context, billingRef string) (Amount, error)
	// GetQuota returns the remaining unit-count quota for an account, or 0 when no
	// cap is configured. A persisted adapter that does not model a unit-count
	// quota MAY always return 0 (no cap); quota parity is therefore not asserted
	// by the shared conformance suite.
	GetQuota(ctx context.Context, billingRef string) (int64, error)
}

// Sentinel errors returned by adapter implementations. Service callers MUST
// use errors.Is to check; adapter implementations MUST return (or wrap) these
// exact values. The service maps each to a connect.Code via
// service.billingErrorKind.
var (
	// ErrUnknownBillingID is returned by Record, Release, or Refund when the
	// billingID was not issued by this adapter, was already recorded, or was
	// already released. Callers treat it as a successful no-op for Release.
	ErrUnknownBillingID = errors.New("billing: unknown billing id")

	// ErrInsufficientBalance is returned by Authorize when available balance
	// is insufficient (distinct from a soft denial in AuthorizeResult).
	ErrInsufficientBalance = errors.New("billing: insufficient balance")

	// ErrInvalidAmount is returned by Refund when the amount is non-positive
	// or the currency does not match the recorded charge.
	ErrInvalidAmount = errors.New("billing: invalid refund amount")

	// ErrAmountNotRepresentable is returned by Authorize when the offer's price
	// cannot be expressed as an exact integer at the ledger's asset scale (finer
	// precision than the scale supports). It is an input-shaped fault — the price
	// is malformed for this ledger — so the service maps it to KindInvalidRequest
	// (a 4xx), not KindInternal. The adapter boundary translates the underlying
	// tigerbeetle.ErrAmountNotRepresentable into this billing sentinel, mirroring
	// how ErrBackendUnavailable mirrors tigerbeetle.ErrUnavailable.
	ErrAmountNotRepresentable = errors.New("billing: amount not representable at asset scale")

	// ErrRefundBeforeRecord is returned by Refund for a billingID that is held
	// but not yet recorded — that hold is voided with Release, not Refund.
	ErrRefundBeforeRecord = errors.New("billing: cannot refund a hold that was not recorded")

	// ErrRefundExceedsRecord is returned by Refund when the cumulative refund
	// would exceed the recorded charge.
	ErrRefundExceedsRecord = errors.New("billing: refund exceeds recorded amount")

	// ErrRefundUnsupported is returned by Refund when the adapter has no native
	// reverse-transfer primitive (e.g. the demo free tier). Callers escalate to
	// manual or settlement-level reconciliation.
	ErrRefundUnsupported = errors.New("billing: refund unsupported by this adapter")

	// ErrBackendUnavailable is returned when the persisted billing backend (the
	// TigerBeetle cluster) did not answer within the per-call deadline. It is
	// retryable — the service maps it to a 503-class KindUnavailable, not a server
	// fault — so an infrastructure outage is distinguishable from a code bug.
	ErrBackendUnavailable = errors.New("billing: backend unavailable")

	// ErrUnknownPayee is returned by Authorize when the settlement has no attested
	// resource-owner payee (empty ResourceOwnerID). ADR-010 amendment A requires
	// every catalog entry to attest its owner and forbids a tenant-id fallback, so
	// a splitting adapter refuses to settle into a shared empty-owner bucket rather
	// than mis-attribute revenue. Non-splitting adapters (free, in-memory) ignore
	// the payee and never return it.
	ErrUnknownPayee = errors.New("billing: resource owner not attested")
)

// errEmptyBillingRef rejects EnsureAgentAccount("") on every adapter. Unexported
// (unlike the sentinels above) because no caller branches on it: the Exchange
// generates the billing_ref before calling, so an empty value is a caller bug
// surfacing as a plain internal error, not a mappable business outcome.
var errEmptyBillingRef = errors.New("billing: empty billing_ref")

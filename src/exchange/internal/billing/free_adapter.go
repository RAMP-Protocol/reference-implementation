package billing

import (
	"context"
	"math"
	"math/big"

	"github.com/oklog/ulid/v2"
)

// FreeAdapter is the demo-tier billing adapter. Every Authorize call is
// approved; Record is a no-op. The Exchange's transaction log is the single
// source of truth for what was issued and to whom — this adapter exists
// solely to satisfy the Adapter interface contract so the hot path is
// identical across paid and free tiers.
type FreeAdapter struct{}

// NewFreeAdapter returns a zero-state FreeAdapter.
func NewFreeAdapter() FreeAdapter { return FreeAdapter{} }

// EnsureAgentAccount is a no-op success: the free tier keeps no ledger, so
// there is no account to create. The empty-ref guard still applies so the
// interface contract is uniform across tiers.
func (FreeAdapter) EnsureAgentAccount(_ context.Context, billingRef string) error {
	if billingRef == "" {
		return errEmptyBillingRef
	}
	return nil
}

// Credit is a no-op success: the free tier keeps no ledger, so there is no
// balance to grant into. The shared argument gate still applies so the
// interface contract is uniform across tiers, and it checks the amount against
// DemoCurrency — the currency GetBalance reports below, so this tier has a
// currency and takes no exemption from the rule.
func (FreeAdapter) Credit(_ context.Context, billingRef string, amount Amount, idempotencyKey string) error {
	return validateCreditArgs(billingRef, amount, idempotencyKey, DemoCurrency)
}

// Authorize always approves and returns a fresh ULID BillingID.
func (FreeAdapter) Authorize(_ context.Context, _ AuthorizeRequest) (AuthorizeResult, error) {
	return AuthorizeResult{
		BillingID: ulid.Make().String(),
		Approved:  true,
	}, nil
}

// Record is a no-op; the transaction log is the canonical record.
func (FreeAdapter) Record(_ context.Context, _ string, _ int64, _ string) error {
	return nil
}

// Release is a no-op; the free tier has no real reservation to release.
func (FreeAdapter) Release(_ context.Context, _ string, _ string) error {
	return nil
}

// Refund is unsupported; the free tier never recorded a charge to reverse.
func (FreeAdapter) Refund(_ context.Context, _ string, _ Amount, _ string, _ string) error {
	return ErrRefundUnsupported
}

// GetBalance reports an effectively unbounded balance in the demo currency.
func (FreeAdapter) GetBalance(_ context.Context, _ string) (Amount, error) {
	return Amount{Value: big.NewRat(math.MaxInt64, 1), Currency: DemoCurrency}, nil
}

// GetQuota reports an effectively unbounded quota.
func (FreeAdapter) GetQuota(_ context.Context, _ string) (int64, error) {
	return math.MaxInt64, nil
}

package billing_test

import (
	"context"
	"errors"
	"math"
	"math/big"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// TestFreeAdapter_SatisfiesAdapterInterface ensures FreeAdapter is usable
// wherever billing.Adapter is required.
func TestFreeAdapter_SatisfiesAdapterInterface(_ *testing.T) {
	var _ billing.Adapter = billing.FreeAdapter{}
	var _ billing.Adapter = billing.NewFreeAdapter()
}

// TestFreeAdapter_ReleaseNoOp proves Release is a no-op for the free tier.
func TestFreeAdapter_ReleaseNoOp(t *testing.T) {
	t.Parallel()
	a := billing.FreeAdapter{}
	for _, id := range []string{"", "bogus-id", "any-id"} {
		if err := a.Release(context.Background(), id, ""); err != nil {
			t.Errorf("Release(%q) = %v, want nil", id, err)
		}
	}
}

// TestFreeAdapter_RefundUnsupported proves Refund reports ErrRefundUnsupported:
// the free tier never recorded a charge to reverse.
func TestFreeAdapter_RefundUnsupported(t *testing.T) {
	t.Parallel()
	a := billing.FreeAdapter{}
	err := a.Refund(context.Background(), "any-id", mustAmount(t, "0.05", "USD"), "dispute", "idem-1")
	if !errors.Is(err, billing.ErrRefundUnsupported) {
		t.Errorf("Refund = %v, want ErrRefundUnsupported", err)
	}
}

// TestFreeAdapter_AuthorizeApproves proves every Authorize call returns
// Approved=true with a non-empty BillingID, regardless of request shape.
func TestFreeAdapter_AuthorizeApproves(t *testing.T) {
	t.Parallel()
	a := billing.FreeAdapter{}

	cases := []billing.AuthorizeRequest{
		{TenantID: "t", AgentID: "ag", UnitCost: billing.Amount{Value: big.NewRat(0, 1), Currency: "USD"}, Quantity: 0},
		{TenantID: "t", AgentID: "ag", UnitCost: billing.Amount{Value: big.NewRat(5, 100), Currency: "USD"}, Quantity: 10, Unit: "tokens"},
		{TenantID: "t", AgentID: "", UnitCost: billing.Amount{Value: big.NewRat(1, 1), Currency: "EUR"}, Quantity: -1},
	}
	for i, req := range cases {
		res, err := a.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("case %d: authorize: %v", i, err)
		}
		if !res.Approved {
			t.Errorf("case %d: expected Approved=true, got reason=%q", i, res.Reason)
		}
		if res.BillingID == "" {
			t.Errorf("case %d: empty BillingID", i)
		}
	}
}

// TestFreeAdapter_AuthorizeUniqueBillingIDs proves that successive Authorize
// calls issue distinct ULIDs.
func TestFreeAdapter_AuthorizeUniqueBillingIDs(t *testing.T) {
	t.Parallel()
	a := billing.FreeAdapter{}
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		res, err := a.Authorize(context.Background(), billing.AuthorizeRequest{AgentID: "ag"})
		if err != nil {
			t.Fatalf("authorize %d: %v", i, err)
		}
		if _, dup := seen[res.BillingID]; dup {
			t.Fatalf("duplicate BillingID %q at i=%d", res.BillingID, i)
		}
		seen[res.BillingID] = struct{}{}
	}
}

// TestFreeAdapter_RecordNoOp proves Record returns nil for any input,
// including IDs this adapter never issued.
func TestFreeAdapter_RecordNoOp(t *testing.T) {
	t.Parallel()
	a := billing.FreeAdapter{}
	inputs := []struct {
		id  string
		qty int64
	}{
		{"", 0},
		{"bogus-id", 0},
		{"bogus-id", 100},
		{"bogus-id", -5},
	}
	for _, in := range inputs {
		if err := a.Record(context.Background(), in.id, in.qty, ""); err != nil {
			t.Errorf("Record(%q, %d) = %v, want nil", in.id, in.qty, err)
		}
	}
}

// TestFreeAdapter_GetBalanceMaxInt64USD proves GetBalance returns an
// effectively unbounded USD amount for any agent.
func TestFreeAdapter_GetBalanceMaxInt64USD(t *testing.T) {
	t.Parallel()
	a := billing.FreeAdapter{}
	for _, agentID := range []string{"", "ag-1", "never-seen"} {
		bal, err := a.GetBalance(context.Background(), agentID)
		if err != nil {
			t.Fatalf("GetBalance(%q): %v", agentID, err)
		}
		if bal.Currency != "USD" {
			t.Errorf("currency = %q, want USD", bal.Currency)
		}
		want := big.NewRat(math.MaxInt64, 1)
		if bal.Value == nil || bal.Value.Cmp(want) != 0 {
			t.Errorf("balance value = %v, want %v", bal.Value, want)
		}
	}
}

// TestFreeAdapter_GetQuotaMaxInt64 proves GetQuota returns MaxInt64.
func TestFreeAdapter_GetQuotaMaxInt64(t *testing.T) {
	t.Parallel()
	a := billing.FreeAdapter{}
	for _, agentID := range []string{"", "ag-1", "never-seen"} {
		q, err := a.GetQuota(context.Background(), agentID)
		if err != nil {
			t.Fatalf("GetQuota(%q): %v", agentID, err)
		}
		if q != math.MaxInt64 {
			t.Errorf("quota = %d, want MaxInt64", q)
		}
	}
}

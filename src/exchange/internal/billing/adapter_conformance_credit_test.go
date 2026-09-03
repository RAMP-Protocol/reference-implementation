package billing_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// ---- credit ----------------------------------------------------------------

// confCreditFundsSpendable mirrors the Register sequence: ensure the account,
// grant the welcome credit, and prove the granted funds are really spendable —
// a hold for exactly the credited amount is approved and settles, after which
// the next paid authorize is denied.
func confCreditFundsSpendable(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{})
	if err := a.EnsureAgentAccount(ctx, "ag"); err != nil {
		t.Fatalf("ensure account: %v", err)
	}
	if err := a.Credit(ctx, "ag", mustAmount(t, "1.00", "USD"), billing.WelcomeCreditKey("ag")); err != nil {
		t.Fatalf("credit: %v", err)
	}
	assertBalance(t, a, "1.00")
	id := authHold(t, a, 20, "k-spend") // reserve 0.05 * 20 = the full 1.00
	if err := a.Record(ctx, id, 20, "k-spend-rec"); err != nil {
		t.Fatalf("record: %v", err)
	}
	assertBalance(t, a, "0.00")
	authDenied(t, a, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
		IdempotencyKey: "k-over", ResourceOwnerID: confResourceOwner,
	})
}

// confCreditSameKeyNoDouble: a replay of an applied key is a no-op success even
// with a different amount — the first credit wins, the grant never tops up.
func confCreditSameKeyNoDouble(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{})
	if err := a.Credit(ctx, "ag", mustAmount(t, "1.00", "USD"), "k-wel"); err != nil {
		t.Fatalf("credit 1: %v", err)
	}
	if err := a.Credit(ctx, "ag", mustAmount(t, "2.00", "USD"), "k-wel"); err != nil {
		t.Fatalf("credit replay (same key) must be a no-op success, got %v", err)
	}
	assertBalance(t, a, "1.00")
}

// confCreditDistinctKeys: distinct keys are distinct grants that accumulate
// (the operator top-up path uses a fresh label per top-up), and the account is
// created on first credit without a prior EnsureAgentAccount.
func confCreditDistinctKeys(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{})
	if err := a.Credit(ctx, "ag", mustAmount(t, "1.00", "USD"), "k-w1"); err != nil {
		t.Fatalf("credit 1: %v", err)
	}
	if err := a.Credit(ctx, "ag", mustAmount(t, "0.50", "USD"), "k-w2"); err != nil {
		t.Fatalf("credit 2: %v", err)
	}
	assertBalance(t, a, "1.50")
}

// confCreditBadArgs: the shared argument gate — empty ref, empty key, a
// reserved key namespace, a missing currency, a currency that is well-formed
// but is not the adapter's, and a nil/zero/negative amount are caller bugs
// rejected with an error, and nothing is credited.
//
// The mismatched-currency case is the one that reaches the currency comparison.
// "empty currency" cannot: the gate rejects an empty currency as a malformed
// amount before any comparison happens. Both conformance factories build their
// adapter in USD, so EUR is a genuine mismatch for each.
func confCreditBadArgs(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{})
	if err := a.EnsureAgentAccount(ctx, "ag"); err != nil {
		t.Fatalf("ensure account: %v", err)
	}
	one := mustAmount(t, "1.00", "USD")
	for name, call := range map[string]func() error{
		"empty ref":            func() error { return a.Credit(ctx, "", one, "k") },
		"empty key":            func() error { return a.Credit(ctx, "ag", one, "") },
		"nil amount":           func() error { return a.Credit(ctx, "ag", billing.Amount{Currency: "USD"}, "k") },
		"zero amount":          func() error { return a.Credit(ctx, "ag", mustAmount(t, "0.00", "USD"), "k") },
		"negative amount":      func() error { return a.Credit(ctx, "ag", mustAmount(t, "-1.00", "USD"), "k") },
		"empty currency":       func() error { return a.Credit(ctx, "ag", billing.Amount{Value: one.Value}, "k") },
		"mismatched currency":  func() error { return a.Credit(ctx, "ag", mustAmount(t, "1.00", "EUR"), "k") },
		"reserved key pending": func() error { return a.Credit(ctx, "ag", one, "pending:ag:k:0") },
		"reserved key post":    func() error { return a.Credit(ctx, "ag", one, "post:abc") },
		"reserved key void":    func() error { return a.Credit(ctx, "ag", one, "void:abc") },
		"reserved key fee":     func() error { return a.Credit(ctx, "ag", one, "fee:abc") },
		"reserved key refund":  func() error { return a.Credit(ctx, "ag", one, "refund:abc") },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A mismatched currency is an input fault, so it reports ErrInvalidAmount
	// and the service maps it to a 4xx instead of a 500.
	if err := a.Credit(ctx, "ag", mustAmount(t, "1.00", "EUR"), "k"); !errors.Is(err, billing.ErrInvalidAmount) {
		t.Errorf("mismatched currency = %v, want ErrInvalidAmount", err)
	}
	assertBalance(t, a, "0.00")
}

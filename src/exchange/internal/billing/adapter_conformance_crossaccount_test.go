package billing_test

import (
	"context"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// Cross-account hold case of the adapter conformance suite (registered in
// runAdapterConformance, adapter_conformance_test.go). It lives in its own file
// so the main conformance file stays under the file-length limit.

// confCrossAccountHold pins the account-scoped hold id: two DIFFERENT billing_refs
// that reuse the SAME idempotency key get two SEPARATE holds, and each Record
// settles only its own account. Before the pending id carried the billing_ref, the
// two accounts collided on one shared hold.
func confCrossAccountHold(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{Balances: map[string]billing.Amount{
		"ag-a": mustAmount(t, "10.00", "USD"),
		"ag-b": mustAmount(t, "10.00", "USD"),
	}})
	const sharedKey = "shared-key"
	authFor := func(ref string) string {
		res, err := a.Authorize(ctx, billing.AuthorizeRequest{
			BillingRef: ref, UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 10,
			IdempotencyKey: sharedKey, ResourceOwnerID: confResourceOwner,
		})
		if err != nil || !res.Approved {
			t.Fatalf("authorize(%q): approved=%v err=%v reason=%q", ref, res.Approved, err, res.Reason)
		}
		return res.BillingID
	}
	idA := authFor("ag-a")
	idB := authFor("ag-b")
	if idA == idB {
		t.Fatalf("two accounts sharing key %q collided on one hold id %q", sharedKey, idA)
	}
	// Each Record settles only its own account: 0.50 off each of the two 10.00 balances.
	if err := a.Record(ctx, idA, 10, "rec-a"); err != nil {
		t.Fatalf("record ag-a: %v", err)
	}
	if err := a.Record(ctx, idB, 10, "rec-b"); err != nil {
		t.Fatalf("record ag-b: %v", err)
	}
	assertBalanceFor(t, a, "ag-a", "9.50")
	assertBalanceFor(t, a, "ag-b", "9.50")
}

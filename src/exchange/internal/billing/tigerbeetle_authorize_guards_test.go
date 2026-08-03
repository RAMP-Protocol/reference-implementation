//go:build integration

package billing_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// TestTigerBeetleAuthorize_NotRepresentableAmount (negative, Testing Doctrine §10):
// a price with finer precision than the ledger's asset scale (scale 8) cannot be
// posted as an exact integer, so Authorize refuses it with
// billing.ErrAmountNotRepresentable — the adapter translates the ledger-layer
// tigerbeetle sentinel into the billing one, and the service maps that to
// KindInvalidRequest (a 4xx), not a 500. InMemory has no scale conversion, so this
// is a persisted-adapter-specific guard, not a shared conformance case.
func TestTigerBeetleAuthorize_NotRepresentableAmount(t *testing.T) {
	adapter, _ := newTBAdapter("notrepr", time.Minute)
	_, err := adapter.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.000000001", "USD"), Quantity: 1,
		IdempotencyKey: "notrepr", ResourceOwnerID: confResourceOwner,
	})
	if !errors.Is(err, billing.ErrAmountNotRepresentable) {
		t.Fatalf("Authorize(9-decimal price at scale 8): err = %v, want ErrAmountNotRepresentable", err)
	}
}

//go:build integration

package billing_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// TestTigerBeetleAuthorize_EmptyPayeeRefused (negative, Testing Doctrine §10) — a
// TigerBeetle Authorize with no attested resource owner is refused with
// ErrUnknownPayee (ADR-010 amendment A: no tenant-id fallback) instead of settling
// into a shared empty-owner bucket. The agent is funded first, so the refusal is
// the payee guard firing ahead of the balance check, not an insufficient balance.
func TestTigerBeetleAuthorize_EmptyPayeeRefused(t *testing.T) {
	adapter, ns := newTBAdapter("emptypayee", time.Minute)
	confLedger().MustFundAgent(t, ns, "ag", "10.00")

	_, err := adapter.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "1.00", "USD"), Quantity: 1,
		IdempotencyKey: "empty-payee", ResourceOwnerID: "",
	})
	if !errors.Is(err, billing.ErrUnknownPayee) {
		t.Fatalf("Authorize with empty owner: err = %v, want ErrUnknownPayee", err)
	}
}

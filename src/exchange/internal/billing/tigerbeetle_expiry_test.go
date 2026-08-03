//go:build integration

package billing_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tbtest"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// TestTigerBeetleExpiry_LateRecordRelease (negative, Testing Doctrine §10) — a hold
// left neither recorded nor released is reclaimed by TigerBeetle when its native
// timeout elapses; a late Record or Release then maps to ErrUnknownBillingID and no
// settlement postings land. It runs at a non-zero fee so Record takes the linked
// split path — the branch that must classify an expired post-pending leg the same
// way the single post-pending path classifies ResolveAlreadyResolved. Uses a real 1s
// timeout and polls observable ledger state (the expiry is real inside TigerBeetle,
// so there is no clock to fake).
func TestTigerBeetleExpiry_LateRecordRelease(t *testing.T) {
	adapter, ns := newTBAdapter("expiry", time.Second) // 1s = minimum native expiry granularity
	led := confLedger()
	led.MustFundAgent(t, ns, "ag", "10.00")
	ctx := context.Background()

	res, err := adapter.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "1.00", "USD"), Quantity: 1,
		IdempotencyKey: "exp", ResourceOwnerID: confResourceOwner, FeeRateBps: 1000,
	})
	if err != nil || !res.Approved {
		t.Fatalf("authorize = (%+v, %v), want approved", res, err)
	}
	agentID := tbtest.MustAccountID(t, tigerbeetle.PrefixAgent, ns+"ag")
	waitPendingCleared(t, led, agentID)

	// Late Record must not settle an expired hold (linked-split path at fee!=0).
	if err := adapter.Record(ctx, res.BillingID, 1, "exp-rec"); !errors.Is(err, billing.ErrUnknownBillingID) {
		t.Fatalf("late Record on expired hold: err = %v, want ErrUnknownBillingID", err)
	}
	// Late Release is likewise a no-op mapped to ErrUnknownBillingID.
	if err := adapter.Release(ctx, res.BillingID, "exp-rel"); !errors.Is(err, billing.ErrUnknownBillingID) {
		t.Fatalf("late Release on expired hold: err = %v, want ErrUnknownBillingID", err)
	}
	// No settlement landed: the agent balance is fully restored.
	if got, want := led.PostedBalance(t, agentID), led.Minor(t, "10.00"); got != want {
		t.Errorf("agent posted = %d, want %d (no settlement after expiry)", got, want)
	}
}

// waitPendingCleared polls the agent's debits_pending until TigerBeetle has
// reclaimed the expired hold (back to 0), bounded at ~10s. Polling observable ledger
// state avoids a blind sleep and keeps the assertion honest.
func waitPendingCleared(t *testing.T, led tbtest.Ledger, agentID tigerbeetle.ID) {
	t.Helper()
	for range 100 {
		if led.PendingBalance(t, agentID) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("pending hold did not expire within ~10s")
}

//go:build integration

package billing_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// These tests drive the split at a non-zero fee (the shared conformance suite runs at
// fee=0). The agent leg is asserted through the tier-1 adapter.GetBalance surface; the
// resource-owner and platform legs have no adapter read surface (GetBalance is
// agent-only), so those go through the shared §9-exception ledger read on tbtest.Ledger
// (AssertOwnerPlatformSplit) — the eventual public read home is the future RevenueReport
// surface.

const (
	splitOwner  = "acme"
	splitSeed   = "10.00" // agent funding for every split test
	splitFeeBps = 1000    // 10%
)

// splitAdapter builds an adapter on the shared cluster under a unique id namespace and
// funds agent "ag" with the seed, returning the adapter and its namespace.
func splitAdapter(t *testing.T) (billing.Adapter, string) {
	t.Helper()
	a, ns := newTBAdapter("split", 0) // 0 → adapter default hold timeout
	if err := fundSeed(context.Background(), ns, conformanceSeed{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, splitSeed, "USD")},
	}); err != nil {
		t.Fatalf("fund seed: %v", err)
	}
	return a, ns
}

// mustMinor converts a decimal-dollar string to integer minor units at asset scale 8.
func mustMinor(t *testing.T, dollars string) int64 {
	t.Helper()
	return confLedger().Minor(t, dollars)
}

func mustAuthorize(t *testing.T, a billing.Adapter, cost string) string {
	t.Helper()
	res, err := a.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, cost, "USD"), Quantity: 1,
		IdempotencyKey: "auth", ResourceOwnerID: splitOwner, FeeRateBps: splitFeeBps,
	})
	if err != nil || !res.Approved {
		t.Fatalf("Authorize = (approved=%v, %v)", res.Approved, err)
	}
	return res.BillingID
}

// assertSplit checks the three balances (agent settled, owner net, platform fee) in
// minor units. The agent leg is read through the tier-1 adapter.GetBalance surface; the
// owner and platform legs (no adapter read surface) go through the shared §9-exception
// ledger read on tbtest.Ledger.
func assertSplit(t *testing.T, a billing.Adapter, ns string, agentBal, owner, platform int64) {
	t.Helper()
	bal, err := a.GetBalance(context.Background(), "ag")
	if err != nil {
		t.Fatalf("GetBalance(agent): %v", err)
	}
	agentMinor, err := tigerbeetle.MinorUnits(bal.Value, tbConfScale)
	if err != nil {
		t.Fatalf("agent balance %s not representable at scale %d: %v", bal.Value, tbConfScale, err)
	}
	if agentMinor.Int64() != agentBal {
		t.Errorf("agent balance = %d, want %d", agentMinor.Int64(), agentBal)
	}
	confLedger().AssertOwnerPlatformSplit(t, ns, splitOwner, owner, platform)
}

// TestSplit_RecordPostsOwnerAndPlatform (AC1): a settled $1.00 @ 10% credits the owner
// net-of-fee and the platform the fee; agent is debited the full gross; net+fee==gross.
func TestSplit_RecordPostsOwnerAndPlatform(t *testing.T) {
	a, ns := splitAdapter(t)
	id := mustAuthorize(t, a, "1.00") // 10%
	if err := a.Record(context.Background(), id, 1, "k"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// gross 1.00 → fee 0.10, net 0.90; agent 10.00 − 1.00 = 9.00.
	assertSplit(t, a, ns, mustMinor(t, "9.00"), mustMinor(t, "0.90"), mustMinor(t, "0.10"))
	if mustMinor(t, "0.90")+mustMinor(t, "0.10") != mustMinor(t, "1.00") {
		t.Fatal("net+fee != gross")
	}
}

// TestSplit_RefundReversesProportionally (AC3): the ADR-010 D4 worked example —
// $1.00 @ 10%, refund $0.30 → agent −0.70, owner +0.63, platform +0.07 (net of the
// original settlement).
func TestSplit_RefundReversesProportionally(t *testing.T) {
	ctx := context.Background()
	a, ns := splitAdapter(t)
	id := mustAuthorize(t, a, "1.00")
	if err := a.Record(ctx, id, 1, "k"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := a.Refund(ctx, id, mustAmount(t, "0.30", "USD"), "dispute", "kr"); err != nil {
		t.Fatalf("Refund: %v", err)
	}
	// agent 9.00 + 0.30 = 9.30; owner 0.90 − 0.27 = 0.63; platform 0.10 − 0.03 = 0.07.
	assertSplit(t, a, ns, mustMinor(t, "9.30"), mustMinor(t, "0.63"), mustMinor(t, "0.07"))
}

// TestSplit_RemainderAbsorbed (§C): a gross that does not divide evenly floors the fee,
// the platform absorbs the sub-unit remainder, and net+fee==gross exactly.
func TestSplit_RemainderAbsorbed(t *testing.T) {
	ctx := context.Background()
	a, ns := splitAdapter(t)
	// gross 0.00012345 = 12345 minor; fee = floor(12345·1000/10000) = 1234; net = 11111.
	id := mustAuthorize(t, a, "0.00012345")
	if err := a.Record(ctx, id, 1, "k"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	gross := int64(12345)
	assertSplit(t, a, ns, mustMinor(t, "10.00")-gross, 11111, 1234)
	if gross != 11111+1234 {
		t.Fatal("net+fee != gross")
	}
}

// TestSplit_IdempotentRecordAndRefund (AC5): replaying Record and Refund with the same
// key is a no-op against every account.
func TestSplit_IdempotentRecordAndRefund(t *testing.T) {
	ctx := context.Background()
	a, ns := splitAdapter(t)
	id := mustAuthorize(t, a, "1.00")
	for range 2 {
		if err := a.Record(ctx, id, 1, "k"); err != nil {
			t.Fatalf("Record replay: %v", err)
		}
	}
	for range 2 {
		if err := a.Refund(ctx, id, mustAmount(t, "0.30", "USD"), "d", "kr"); err != nil {
			t.Fatalf("Refund replay: %v", err)
		}
	}
	assertSplit(t, a, ns, mustMinor(t, "9.30"), mustMinor(t, "0.63"), mustMinor(t, "0.07"))
}

// TestSplit_CumulativeCapWithFee (AC6): three partial refunds accumulate against the
// original gross; a fourth that would exceed it is rejected with no ledger movement.
func TestSplit_CumulativeCapWithFee(t *testing.T) {
	ctx := context.Background()
	a, ns := splitAdapter(t)
	id := mustAuthorize(t, a, "1.00")
	if err := a.Record(ctx, id, 1, "k"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	for i, key := range []string{"r1", "r2", "r3"} {
		if err := a.Refund(ctx, id, mustAmount(t, "0.30", "USD"), "d", key); err != nil {
			t.Fatalf("refund %d: %v", i+1, err)
		}
	}
	// 0.90 refunded: agent 9.90, owner 0.90−0.81=0.09, platform 0.10−0.09=0.01.
	assertSplit(t, a, ns, mustMinor(t, "9.90"), mustMinor(t, "0.09"), mustMinor(t, "0.01"))
	// A fourth 0.30 pushes cumulative to 1.20 > 1.00 recorded.
	if err := a.Refund(ctx, id, mustAmount(t, "0.30", "USD"), "d", "r4"); !errors.Is(err, billing.ErrRefundExceedsRecord) {
		t.Fatalf("4th refund = %v, want ErrRefundExceedsRecord", err)
	}
	assertSplit(t, a, ns, mustMinor(t, "9.90"), mustMinor(t, "0.09"), mustMinor(t, "0.01")) // unchanged
}

// TestSplit_RefundInvalidCurrency (negative, §10): a refund whose currency does not
// match the ledger is rejected with ErrInvalidAmount and no movement.
func TestSplit_RefundInvalidCurrency(t *testing.T) {
	ctx := context.Background()
	a, ns := splitAdapter(t)
	id := mustAuthorize(t, a, "1.00")
	if err := a.Record(ctx, id, 1, "k"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := a.Refund(ctx, id, mustAmount(t, "0.30", "EUR"), "d", "kr"); !errors.Is(err, billing.ErrInvalidAmount) {
		t.Fatalf("refund(EUR) = %v, want ErrInvalidAmount", err)
	}
	assertSplit(t, a, ns, mustMinor(t, "9.00"), mustMinor(t, "0.90"), mustMinor(t, "0.10")) // unchanged
}

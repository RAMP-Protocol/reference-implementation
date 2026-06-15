package billing_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// Adapter conformance suite. These assertions define the cross-adapter
// behavioral contract for any balance-bearing billing.Adapter. InMemoryAdapter
// runs it today; a future persisted-ledger adapter (e.g. TigerBeetle) registers
// the same factory so this file becomes its behavioral spec. The demo
// FreeAdapter is a no-op and is exercised separately in free_adapter_test.go.

type conformanceSeed struct {
	Balances map[string]billing.Amount
	Quotas   map[string]int64
}

type adapterFactory struct {
	name string
	new  func(seed conformanceSeed) billing.Adapter
}

func conformanceFactories() []adapterFactory {
	return []adapterFactory{
		{
			name: "InMemoryAdapter",
			new: func(seed conformanceSeed) billing.Adapter {
				return billing.NewInMemoryAdapter(billing.InMemoryOptions{
					Balances: seed.Balances,
					Quotas:   seed.Quotas,
				})
			},
		},
	}
}

func TestAdapterConformance(t *testing.T) {
	t.Parallel()
	for _, f := range conformanceFactories() {
		runAdapterConformance(t, f)
	}
}

// runAdapterConformance takes the factory by value (no loop-var capture) so
// every subtest may run in parallel safely.
func runAdapterConformance(t *testing.T, f adapterFactory) {
	t.Run(f.name, func(t *testing.T) {
		t.Parallel()
		t.Run("Record_Debits_ReservedAmount", func(t *testing.T) { confRecordDebits(t, f) })
		t.Run("Release_FreesReservation", func(t *testing.T) { confReleaseFrees(t, f) })
		t.Run("Authorize_Idempotent_WhileLive", func(t *testing.T) { confAuthorizeIdempotent(t, f) })
		t.Run("Authorize_AfterRelease_ReAuthorizes", func(t *testing.T) { confReauthorizeAfterRelease(t, f) })
		t.Run("Authorize_AfterRecord_ReAuthorizes", func(t *testing.T) { confReauthorizeAfterRecord(t, f) })
		t.Run("Record_Idempotent", func(t *testing.T) { confRecordIdempotent(t, f) })
		t.Run("Release_Idempotent", func(t *testing.T) { confReleaseIdempotent(t, f) })
		t.Run("Release_UnknownID", func(t *testing.T) { confReleaseUnknown(t, f) })
		t.Run("Record_UnknownID", func(t *testing.T) { confRecordUnknown(t, f) })
		t.Run("Refund_Full_RestoresBalance", func(t *testing.T) { confRefundFull(t, f) })
		t.Run("Refund_Partial", func(t *testing.T) { confRefundPartial(t, f) })
		t.Run("Refund_Idempotent", func(t *testing.T) { confRefundIdempotent(t, f) })
		t.Run("Refund_UnknownID", func(t *testing.T) { confRefundUnknown(t, f) })
		t.Run("Refund_BeforeRecord", func(t *testing.T) { confRefundBeforeRecord(t, f) })
		t.Run("Refund_ExceedsRecord", func(t *testing.T) { confRefundExceeds(t, f) })
		t.Run("Refund_Cumulative", func(t *testing.T) { confRefundCumulative(t, f) })
	})
}

// ---- shared helpers --------------------------------------------------------

func seedTen(t *testing.T, f adapterFactory) billing.Adapter {
	t.Helper()
	return f.new(conformanceSeed{Balances: map[string]billing.Amount{"ag": mustAmount(t, "10.00", "USD")}})
}

// authHold authorizes a 0.05 × qty USD hold for agent "ag" and returns the id.
func authHold(t *testing.T, a billing.Adapter, qty int64, key string) string {
	t.Helper()
	res, err := a.Authorize(context.Background(), billing.AuthorizeRequest{
		AgentID: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: qty, IdempotencyKey: key,
	})
	if err != nil || !res.Approved {
		t.Fatalf("authorize(qty=%d): approved=%v err=%v reason=%q", qty, res.Approved, err, res.Reason)
	}
	return res.BillingID
}

func assertBalance(t *testing.T, a billing.Adapter, want string) {
	t.Helper()
	bal, err := a.GetBalance(context.Background(), "ag")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if w := mustAmount(t, want, "USD"); bal.Value.Cmp(w.Value) != 0 {
		t.Errorf("balance = %s, want %s", bal.Value.FloatString(4), want)
	}
}

// ---- lifecycle -------------------------------------------------------------

func confRecordDebits(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	id := authHold(t, a, 10, "k-auth") // reserve 0.05 * 10 = 0.50
	assertBalance(t, a, "10.00")       // unchanged after Authorize
	if err := a.Record(ctx, id, 10, "k-rec"); err != nil {
		t.Fatalf("record: %v", err)
	}
	assertBalance(t, a, "9.50")
}

func confReleaseFrees(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "USD")}})
	id := authHold(t, a, 12, "k-hold") // reserve 0.60; available now 0.40
	denied, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		AgentID: "ag", UnitCost: mustAmount(t, "0.50", "USD"), Quantity: 1, IdempotencyKey: "k-x",
	})
	if denied.Approved {
		t.Fatal("expected denial while 0.60 reserved (available 0.40 < 0.50)")
	}
	if err := a.Release(ctx, id, "k-hold"); err != nil {
		t.Fatalf("release: %v", err)
	}
	assertBalance(t, a, "1.00")
	ok, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		AgentID: "ag", UnitCost: mustAmount(t, "0.50", "USD"), Quantity: 1, IdempotencyKey: "k-y",
	})
	if !ok.Approved {
		t.Fatalf("expected approval after release: %s", ok.Reason)
	}
}

// ---- idempotency -----------------------------------------------------------

func confAuthorizeIdempotent(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "USD")}})
	first := authHold(t, a, 1, "k-same")  // reserve 0.05
	second := authHold(t, a, 1, "k-same") // same key, hold still live
	if first != second {
		t.Fatalf("same-key Authorize returned different ids %q vs %q", first, second)
	}
	// Single reservation (0.05): a distinct-key Authorize for exactly the
	// remaining 0.95 must be approved. Two reservations (0.10) would deny it.
	res, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		AgentID: "ag", UnitCost: mustAmount(t, "0.95", "USD"), Quantity: 1, IdempotencyKey: "k-other",
	})
	if !res.Approved {
		t.Fatalf("distinct-key Authorize for 0.95 denied → more than one reservation held: %s", res.Reason)
	}
}

func confReauthorizeAfterRelease(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	first := authHold(t, a, 1, "k-retry")
	if err := a.Release(ctx, first, "k-retry"); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Same key after Release must mint a FRESH id (the prior hold was voided).
	second := authHold(t, a, 1, "k-retry")
	if first == second {
		t.Fatalf("same-key Authorize after Release reused voided id %q (charge-leak)", first)
	}
	if err := a.Record(ctx, second, 1, "k-retry-rec"); err != nil {
		t.Fatalf("record after re-authorize: %v", err)
	}
	assertBalance(t, a, "9.95") // charged once on the fresh hold
}

func confReauthorizeAfterRecord(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	first := authHold(t, a, 1, "k-retry")
	if err := a.Record(ctx, first, 1, "k-retry-rec"); err != nil {
		t.Fatalf("record: %v", err)
	}
	// Record frees the dedup key just like Release: a same-key Authorize after
	// Record must mint a FRESH id, not hand back the settled hold.
	second := authHold(t, a, 1, "k-retry")
	if first == second {
		t.Fatalf("same-key Authorize after Record reused settled id %q", first)
	}
	if err := a.Record(ctx, second, 1, "k-retry-rec-2"); err != nil {
		t.Fatalf("record after re-authorize: %v", err)
	}
	assertBalance(t, a, "9.90") // two distinct 0.05 holds settled
}

func confRecordIdempotent(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	id := authHold(t, a, 10, "k-auth")
	if err := a.Record(ctx, id, 10, "k-rec"); err != nil {
		t.Fatalf("record 1: %v", err)
	}
	if err := a.Record(ctx, id, 10, "k-rec"); err != nil {
		t.Fatalf("record replay (same key) must be a no-op success, got %v", err)
	}
	assertBalance(t, a, "9.50") // debited once
}

func confReleaseIdempotent(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "USD")}})
	id := authHold(t, a, 1, "k-auth")
	if err := a.Release(ctx, id, "k-rel"); err != nil {
		t.Fatalf("release 1: %v", err)
	}
	if err := a.Release(ctx, id, "k-rel"); err != nil {
		t.Fatalf("release replay (same key) must be a no-op success, got %v", err)
	}
	assertBalance(t, a, "1.00")
}

func confReleaseUnknown(t *testing.T, f adapterFactory) {
	a := seedTen(t, f)
	if err := a.Release(context.Background(), "no-such-id", "k"); !errors.Is(err, billing.ErrUnknownBillingID) {
		t.Fatalf("Release(unknown) = %v, want ErrUnknownBillingID", err)
	}
}

func confRecordUnknown(t *testing.T, f adapterFactory) {
	a := seedTen(t, f)
	if err := a.Record(context.Background(), "no-such-id", 1, "k"); !errors.Is(err, billing.ErrUnknownBillingID) {
		t.Fatalf("Record(unknown) = %v, want ErrUnknownBillingID", err)
	}
}

// ---- refund ----------------------------------------------------------------

func confRefundFull(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	id := authHold(t, a, 10, "k-auth")
	if err := a.Record(ctx, id, 10, "k-rec"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := a.Refund(ctx, id, mustAmount(t, "0.50", "USD"), "dispute", "k-ref"); err != nil {
		t.Fatalf("refund: %v", err)
	}
	assertBalance(t, a, "10.00")
}

func confRefundPartial(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	id := authHold(t, a, 20, "k-auth") // reserve 1.00
	if err := a.Record(ctx, id, 20, "k-rec"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := a.Refund(ctx, id, mustAmount(t, "0.30", "USD"), "partial", "k-ref"); err != nil {
		t.Fatalf("refund: %v", err)
	}
	assertBalance(t, a, "9.30") // net charge 0.70
}

func confRefundIdempotent(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	id := authHold(t, a, 10, "k-auth")
	if err := a.Record(ctx, id, 10, "k-rec"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := a.Refund(ctx, id, mustAmount(t, "0.50", "USD"), "dispute", "k-ref"); err != nil {
		t.Fatalf("refund 1: %v", err)
	}
	if err := a.Refund(ctx, id, mustAmount(t, "0.50", "USD"), "dispute", "k-ref"); err != nil {
		t.Fatalf("refund replay (same key) must be a no-op success, got %v", err)
	}
	assertBalance(t, a, "10.00") // credited once
}

func confRefundCumulative(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	id := authHold(t, a, 20, "k-auth") // reserve 1.00
	if err := a.Record(ctx, id, 20, "k-rec"); err != nil {
		t.Fatalf("record: %v", err)
	}
	// Three 0.30 partials accumulate against the 1.00 recorded charge.
	for i, key := range []string{"k-r1", "k-r2", "k-r3"} {
		if err := a.Refund(ctx, id, mustAmount(t, "0.30", "USD"), "partial", key); err != nil {
			t.Fatalf("refund %d: %v", i+1, err)
		}
	}
	assertBalance(t, a, "9.90") // 10.00 - 1.00 recorded + 0.90 refunded
	// A fourth 0.30 pushes cumulative refunds to 1.20 > 1.00 recorded.
	if err := a.Refund(ctx, id, mustAmount(t, "0.30", "USD"), "partial", "k-r4"); !errors.Is(err, billing.ErrRefundExceedsRecord) {
		t.Fatalf("4th refund = %v, want ErrRefundExceedsRecord", err)
	}
	assertBalance(t, a, "9.90") // unchanged after the rejected refund
}

func confRefundUnknown(t *testing.T, f adapterFactory) {
	a := seedTen(t, f)
	err := a.Refund(context.Background(), "no-such-id", mustAmount(t, "0.05", "USD"), "x", "k")
	if !errors.Is(err, billing.ErrUnknownBillingID) {
		t.Fatalf("Refund(unknown) = %v, want ErrUnknownBillingID", err)
	}
}

func confRefundBeforeRecord(t *testing.T, f adapterFactory) {
	a := seedTen(t, f)
	id := authHold(t, a, 10, "k-auth") // held, never recorded
	err := a.Refund(context.Background(), id, mustAmount(t, "0.50", "USD"), "x", "k-ref")
	if !errors.Is(err, billing.ErrRefundBeforeRecord) {
		t.Fatalf("Refund(held-not-recorded) = %v, want ErrRefundBeforeRecord", err)
	}
}

func confRefundExceeds(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	id := authHold(t, a, 10, "k-auth") // recorded 0.50
	if err := a.Record(ctx, id, 10, "k-rec"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := a.Refund(ctx, id, mustAmount(t, "0.60", "USD"), "x", "k-ref"); !errors.Is(err, billing.ErrRefundExceedsRecord) {
		t.Fatalf("Refund(0.60 > recorded 0.50) = %v, want ErrRefundExceedsRecord", err)
	}
	assertBalance(t, a, "9.50") // unchanged
}

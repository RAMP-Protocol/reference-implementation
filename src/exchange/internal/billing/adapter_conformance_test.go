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

// confResourceOwner is the attested payee every conformance Authorize passes. A
// splitting adapter (TigerBeetle) refuses an empty ResourceOwnerID with
// ErrUnknownPayee; a non-splitting adapter ignores it. Keeping it non-empty drives
// the real attested-payee path on both.
const confResourceOwner = "conf-owner"

type conformanceSeed struct {
	Balances map[string]billing.Amount
	Quotas   map[string]int64
}

type adapterFactory struct {
	name string
	new  func(seed conformanceSeed) billing.Adapter
	// supportsRefund gates the Refund_* cases. Both InMemoryAdapter and
	// TigerBeetleAdapter set it; an adapter with no reversal primitive leaves it false.
	supportsRefund bool
	// requiresIdempotencyKey selects the empty-key case: a persisted adapter
	// (TigerBeetle) soft-denies an empty key, while InMemory executes it fresh.
	requiresIdempotencyKey bool
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
			supportsRefund: true,
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
		t.Run("EnsureAgentAccount_Idempotent_ZeroBalance", func(t *testing.T) { confEnsureAgentAccount(t, f) })
		t.Run("EnsureAgentAccount_FundedAccount_BalancePreserved", func(t *testing.T) { confEnsureAgentAccountFunded(t, f) })
		t.Run("EnsureAgentAccount_EmptyRef_Rejected", func(t *testing.T) { confEnsureAgentAccountEmptyRef(t, f) })
		t.Run("Record_Debits_ReservedAmount", func(t *testing.T) { confRecordDebits(t, f) })
		t.Run("Release_FreesReservation", func(t *testing.T) { confReleaseFrees(t, f) })
		t.Run("Authorize_Idempotent_WhileLive", func(t *testing.T) { confAuthorizeIdempotent(t, f) })
		t.Run("Authorize_CrossAccount_SameKey_TwoHolds", func(t *testing.T) { confCrossAccountHold(t, f) })
		t.Run("Authorize_AfterRelease_ReAuthorizes", func(t *testing.T) { confReauthorizeAfterRelease(t, f) })
		t.Run("Authorize_AfterRecord_ReAuthorizes", func(t *testing.T) { confReauthorizeAfterRecord(t, f) })
		t.Run("Record_Idempotent", func(t *testing.T) { confRecordIdempotent(t, f) })
		t.Run("Release_Idempotent", func(t *testing.T) { confReleaseIdempotent(t, f) })
		t.Run("Release_UnknownID", func(t *testing.T) { confReleaseUnknown(t, f) })
		t.Run("Record_UnknownID", func(t *testing.T) { confRecordUnknown(t, f) })
		// Authorize-guard cases: shared assertions both adapters satisfy.
		t.Run("Authorize_CurrencyMismatch_Denied", func(t *testing.T) { confCurrencyMismatch(t, f) })
		t.Run("Authorize_ZeroCost_SettlesNothing", func(t *testing.T) { confZeroCost(t, f) })
		t.Run("Authorize_UnknownAgent_Denied", func(t *testing.T) { confUnknownAgentDenied(t, f) })
		t.Run("Authorize_EmptyBillingRef_Denied", func(t *testing.T) { confEmptyRefDenied(t, f) })
		// Empty-key behavior is capability-split: a persisted adapter refuses it, a
		// dedup-map adapter executes it fresh. Same contract, two valid resolutions.
		if f.requiresIdempotencyKey {
			t.Run("Authorize_EmptyKey_Denied", func(t *testing.T) { confEmptyKeyDenied(t, f) })
		} else {
			t.Run("Authorize_EmptyKey_ExecutesFresh", func(t *testing.T) { confEmptyKeyExecutesFresh(t, f) })
		}
		// supportsRefund gates the refund cases on the factory capability: an adapter
		// with no reversal primitive leaves it false and skips them, rather than
		// weakening the assertions. Both InMemory and TigerBeetle set it true.
		if f.supportsRefund {
			t.Run("Refund_Full_RestoresBalance", func(t *testing.T) { confRefundFull(t, f) })
			t.Run("Refund_Partial", func(t *testing.T) { confRefundPartial(t, f) })
			t.Run("Refund_Idempotent", func(t *testing.T) { confRefundIdempotent(t, f) })
			t.Run("Refund_UnknownID", func(t *testing.T) { confRefundUnknown(t, f) })
			t.Run("Refund_BeforeRecord", func(t *testing.T) { confRefundBeforeRecord(t, f) })
			t.Run("Refund_ExceedsRecord", func(t *testing.T) { confRefundExceeds(t, f) })
			t.Run("Refund_Cumulative", func(t *testing.T) { confRefundCumulative(t, f) })
		}
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
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: qty,
		IdempotencyKey: key, ResourceOwnerID: confResourceOwner,
	})
	if err != nil || !res.Approved {
		t.Fatalf("authorize(qty=%d): approved=%v err=%v reason=%q", qty, res.Approved, err, res.Reason)
	}
	// An approved authorize MUST return a non-empty reservation handle. The
	// service keys the Record/Release lifecycle off "handle present"; the
	// price-zero free path (no handle) is decided upstream, never by an adapter
	// approving with an empty handle. Every balance-bearing adapter honors this.
	if res.BillingID == "" {
		t.Fatalf("authorize(qty=%d): approved with an empty BillingID; want a reservation handle", qty)
	}
	return res.BillingID
}

func assertBalance(t *testing.T, a billing.Adapter, want string) {
	t.Helper()
	assertBalanceFor(t, a, "ag", want)
}

// assertBalanceFor asserts the settled USD balance of an arbitrary billing_ref.
func assertBalanceFor(t *testing.T, a billing.Adapter, ref, want string) {
	t.Helper()
	bal, err := a.GetBalance(context.Background(), ref)
	if err != nil {
		t.Fatalf("GetBalance(%q): %v", ref, err)
	}
	if w := mustAmount(t, want, "USD"); bal.Value.Cmp(w.Value) != 0 {
		t.Errorf("balance(%q) = %s, want %s", ref, bal.Value.FloatString(4), want)
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
		BillingRef: "ag", UnitCost: mustAmount(t, "0.50", "USD"), Quantity: 1,
		IdempotencyKey: "k-x", ResourceOwnerID: confResourceOwner,
	})
	if denied.Approved {
		t.Fatal("expected denial while 0.60 reserved (available 0.40 < 0.50)")
	}
	if err := a.Release(ctx, id, "k-hold"); err != nil {
		t.Fatalf("release: %v", err)
	}
	assertBalance(t, a, "1.00")
	ok, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.50", "USD"), Quantity: 1,
		IdempotencyKey: "k-y", ResourceOwnerID: confResourceOwner,
	})
	if !ok.Approved {
		t.Fatalf("expected approval after release: %s", ok.Reason)
	}
}

// ---- authorize guards ------------------------------------------------------

// authDenied authorizes req and asserts a soft denial (Approved=false, no error) —
// the shape both adapters use for a refused-but-not-erroring authorize.
func authDenied(t *testing.T, a billing.Adapter, req billing.AuthorizeRequest) {
	t.Helper()
	res, err := a.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("authorize: unexpected error %v (want soft denial)", err)
	}
	if res.Approved {
		t.Fatalf("authorize approved, want denial (reason=%q)", res.Reason)
	}
}

// confCurrencyMismatch: a non-zero charge whose currency differs from the ledger
// currency is denied on both adapters, with no debit — the money-in path must not
// silently relabel a foreign-currency price into the ledger's units.
func confCurrencyMismatch(t *testing.T, f adapterFactory) {
	a := seedTen(t, f)
	authDenied(t, a, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "EUR"), Quantity: 1,
		IdempotencyKey: "k-cur", ResourceOwnerID: confResourceOwner,
	})
	assertBalance(t, a, "10.00")
}

// confZeroCost: a zero-cost term is approved and settles nothing — the balance is
// untouched after Record. (TigerBeetle books a real zero-amount pending; InMemory
// short-circuits. Both end at "nothing charged".)
func confZeroCost(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	res, err := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.00", "USD"), Quantity: 5,
		IdempotencyKey: "k-zero", ResourceOwnerID: confResourceOwner,
	})
	if err != nil || !res.Approved {
		t.Fatalf("zero-cost authorize: approved=%v err=%v", res.Approved, err)
	}
	if err := a.Record(ctx, res.BillingID, 5, "k-zero-rec"); err != nil {
		t.Fatalf("record zero-cost: %v", err)
	}
	assertBalance(t, a, "10.00")
}

// confUnknownAgentDenied: a non-zero charge for an agent with no balance is denied
// on both adapters. The reason legitimately differs (InMemory "unknown account";
// TigerBeetle lazily creates the account and denies "insufficient balance"), so
// only the denial is asserted, not the reason string.
func confUnknownAgentDenied(t *testing.T, f adapterFactory) {
	a := f.new(conformanceSeed{Balances: map[string]billing.Amount{}})
	authDenied(t, a, billing.AuthorizeRequest{
		BillingRef: "ghost", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
		IdempotencyKey: "k-ghost", ResourceOwnerID: confResourceOwner,
	})
}

// confEmptyRefDenied: a non-zero charge with an empty billing_ref is denied on
// both adapters, with no debit. The service already refuses an unregistered
// agent (no ref) before calling Authorize, so this pins the adapters' own
// backstop. The reason legitimately differs (InMemory finds no account under
// the empty key; TigerBeetle refuses the ref outright so unregistered callers
// can never share one ref-independent account), so only the denial is asserted.
func confEmptyRefDenied(t *testing.T, f adapterFactory) {
	a := seedTen(t, f)
	authDenied(t, a, billing.AuthorizeRequest{
		BillingRef: "", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
		IdempotencyKey: "k-noref", ResourceOwnerID: confResourceOwner,
	})
	assertBalance(t, a, "10.00")
}

// confEmptyKeyDenied (requiresIdempotencyKey): a persisted adapter refuses an empty
// idempotency key — a keyless hold would collapse to one shared, agent-independent id.
func confEmptyKeyDenied(t *testing.T, f adapterFactory) {
	a := seedTen(t, f)
	authDenied(t, a, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
		IdempotencyKey: "", ResourceOwnerID: confResourceOwner,
	})
}

// confEmptyKeyExecutesFresh (!requiresIdempotencyKey): an empty key disables dedup —
// each authorize executes fresh with a distinct id.
func confEmptyKeyExecutesFresh(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := seedTen(t, f)
	req := billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
		IdempotencyKey: "", ResourceOwnerID: confResourceOwner,
	}
	first, err := a.Authorize(ctx, req)
	if err != nil || !first.Approved {
		t.Fatalf("first empty-key authorize: approved=%v err=%v", first.Approved, err)
	}
	second, err := a.Authorize(ctx, req)
	if err != nil || !second.Approved {
		t.Fatalf("second empty-key authorize: approved=%v err=%v", second.Approved, err)
	}
	if first.BillingID == second.BillingID {
		t.Fatal("empty key must disable dedup: each authorize gets a fresh id")
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
		BillingRef: "ag", UnitCost: mustAmount(t, "0.95", "USD"), Quantity: 1,
		IdempotencyKey: "k-other", ResourceOwnerID: confResourceOwner,
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

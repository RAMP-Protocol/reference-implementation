package billing_test

import (
	"context"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// mustAmount is the shared decimal-amount helper for the billing_test package
// (used by both this file and adapter_conformance_test.go).
func mustAmount(t *testing.T, raw, currency string) billing.Amount {
	t.Helper()
	a, err := billing.NewAmount(raw, currency)
	if err != nil {
		t.Fatalf("NewAmount: %v", err)
	}
	return a
}

// The generic lifecycle / idempotency / refund / unknown-id contract lives in
// adapter_conformance_test.go (shared with the future TigerBeetle adapter).
// The tests below pin InMemory-specific balance and quota arithmetic.

// TestInMemoryAdapter_ReservationPreventsDoubleSpend verifies that two
// concurrent Authorize calls cannot together exceed the balance.
func TestInMemoryAdapter_ReservationPreventsDoubleSpend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "USD")},
	})

	res1, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag",
		UnitCost:   mustAmount(t, "0.70", "USD"),
		Quantity:   1,
	})
	if !res1.Approved {
		t.Fatal("expected first approval")
	}
	res2, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag",
		UnitCost:   mustAmount(t, "0.40", "USD"),
		Quantity:   1,
	})
	if res2.Approved {
		t.Fatal("second authorize must be denied (0.70 reserved + 0.40 > 1.00)")
	}
}

func TestInMemoryAdapter_InsufficientBalance(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "0.01", "USD")},
	})
	res, err := a.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 5,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if res.Approved {
		t.Fatal("expected denial")
	}
	if res.Reason != "insufficient balance" {
		t.Errorf("reason = %q", res.Reason)
	}
}

func TestInMemoryAdapter_CurrencyMismatch(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "EUR")},
	})
	res, _ := a.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
	})
	if res.Approved {
		t.Fatal("expected denial on currency mismatch")
	}
}

// TestInMemoryAdapter_ZeroCostBypassesCurrencyGate reproduces the zero-cost currency-gate bug:
// a zero-cost term denominated in a currency the agent does NOT hold must be
// AUTHORIZED. There is nothing to charge, so the currency/balance gate has no
// business refusing it. The agent here holds only EUR; the term is priced 0.00
// USD (the canonical EUR feed re-denominated USD was the e2e workaround this
// fix retires). Before the fix the adapter answered "currency mismatch".
func TestInMemoryAdapter_ZeroCostBypassesCurrencyGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "EUR")},
	})
	// FREE / rate-0 term priced in USD; agent holds only EUR.
	res, err := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.00", "USD"), Quantity: 1,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !res.Approved {
		t.Fatalf("zero-cost term in non-held currency must be approved, got denial: %q", res.Reason)
	}
	if res.BillingID == "" {
		t.Fatal("approved zero-cost authorize must still mint a BillingID")
	}
	// Recording the zero-charge hold must settle nothing and must not corrupt the
	// EUR balance (the agent was never charged in USD).
	if err := a.Record(ctx, res.BillingID, 1, ""); err != nil {
		t.Fatalf("record zero-charge hold: %v", err)
	}
	bal, _ := a.GetBalance(ctx, "ag")
	want, _ := billing.NewAmount("1.00", "EUR")
	if bal.Currency != "EUR" || bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance after zero-charge record = %s %s, want 1.00 EUR",
			bal.Value.FloatString(4), bal.Currency)
	}
}

// TestInMemoryAdapter_PerUnitRateZeroBypassesCurrencyGate covers the PER_UNIT
// rate-0 shape of a zero-cost term (rate 0 over a quantity > 1): the total
// charge is still 0, so the same currency-gate bypass applies.
func TestInMemoryAdapter_PerUnitRateZeroBypassesCurrencyGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "EUR")},
	})
	res, err := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.00", "USD"), Quantity: 500,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !res.Approved {
		t.Fatalf("PER_UNIT rate-0 term in non-held currency must be approved, got: %q", res.Reason)
	}
}

// TestInMemoryAdapter_ZeroCostStillEnforcesQuota verifies that the zero-cost
// bypass relaxes ONLY the currency/balance gate, not the quota cap. Quota is a
// unit-count constraint independent of money: a zero-priced term that exceeds
// the agent's remaining quota is still refused.
func TestInMemoryAdapter_ZeroCostStillEnforcesQuota(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "EUR")},
		Quotas:   map[string]int64{"ag": 1},
	})
	res, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.00", "USD"), Quantity: 2,
	})
	if res.Approved {
		t.Fatalf("zero-cost term exceeding quota must still be denied, got approval")
	}
	if res.Reason != "quota exhausted" {
		t.Errorf("reason = %q, want quota exhausted", res.Reason)
	}
}

// TestInMemoryAdapter_ZeroCostUnknownAgentStillDenied verifies the bypass does
// not extend to an agent the adapter has never seen: the prepaid adapter still
// requires the agent to exist (the all-free tier is the FreeAdapter's job).
func TestInMemoryAdapter_ZeroCostUnknownAgentStillDenied(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{})
	res, _ := a.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "nope", UnitCost: mustAmount(t, "0.00", "USD"), Quantity: 1,
	})
	if res.Approved {
		t.Fatal("zero-cost term for unknown agent must still be denied")
	}
	if res.Reason != "unknown account" {
		t.Errorf("reason = %q, want unknown account", res.Reason)
	}
}

// TestInMemoryAdapter_NonZeroCurrencyMismatchStillDenied is the matrix guard:
// a NON-zero term in a currency the agent does not hold MUST still be refused.
// The zero-cost bypass must not weaken real billing.
func TestInMemoryAdapter_NonZeroCurrencyMismatchStillDenied(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "EUR")},
	})
	res, _ := a.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
	})
	if res.Approved {
		t.Fatal("non-zero term in non-held currency must be denied")
	}
	if res.Reason != "currency mismatch" {
		t.Errorf("reason = %q, want currency mismatch", res.Reason)
	}
}

func TestInMemoryAdapter_UnknownAgent(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{})
	res, _ := a.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "nope", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
	})
	if res.Approved {
		t.Fatal("unknown agent must be denied")
	}
}

func TestInMemoryAdapter_QuotaExhausted(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "USD")},
		Quotas:   map[string]int64{"ag": 1},
	})
	res, _ := a.Authorize(context.Background(), billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 2,
	})
	if res.Approved {
		t.Fatal("expected quota denial")
	}
}

func TestInMemoryAdapter_GetQuotaUnknown(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{})
	q, err := a.GetQuota(context.Background(), "ag")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if q != 0 {
		t.Errorf("quota = %d", q)
	}
}

// TestInMemoryAdapter_RefundPersistsReason verifies the dispute memo is retained
// on the refund log (ADR-011 D7 inverse-posting memo).
func TestInMemoryAdapter_RefundPersistsReason(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "10.00", "USD")},
	})
	res, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 10,
	})
	if err := a.Record(ctx, res.BillingID, 10, ""); err != nil {
		t.Fatalf("record: %v", err)
	}
	const memo = "dispute-XYZ resolved in agent favour"
	if err := a.Refund(ctx, res.BillingID, mustAmount(t, "0.20", "USD"), memo, "k-ref"); err != nil {
		t.Fatalf("refund: %v", err)
	}
	log := a.RefundLog(res.BillingID)
	if len(log) != 1 {
		t.Fatalf("RefundLog len = %d, want 1", len(log))
	}
	if log[0].Reason != memo {
		t.Errorf("Reason = %q, want %q", log[0].Reason, memo)
	}
	if log[0].Key != "k-ref" {
		t.Errorf("Key = %q, want k-ref", log[0].Key)
	}
}

// TestInMemoryAdapter_LongIdempotencyKeyStillDedups verifies an over-long key
// (beyond the adapter's stored-size bound) still dedups correctly — boundKey
// hashes it consistently on both the set and lookup paths.
func TestInMemoryAdapter_LongIdempotencyKeyStillDedups(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "10.00", "USD")},
	})
	longKey := strings.Repeat("x", 4096) // well past the 256-byte bound
	first, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1, IdempotencyKey: longKey,
	})
	second, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1, IdempotencyKey: longKey,
	})
	if !first.Approved {
		t.Fatalf("first authorize denied: %s", first.Reason)
	}
	if first.BillingID != second.BillingID {
		t.Fatalf("long-key Authorize not deduped: %q vs %q", first.BillingID, second.BillingID)
	}
}

// TestInMemoryAdapter_RecordSettlesReservedAmountNotPassedQty verifies:
// Record settles the amount Authorize reserved, regardless of the
// (advisory) quantity passed to Record. A divergent quantity — including 0 or a
// negative — must NOT change the settled charge.
func TestInMemoryAdapter_RecordSettlesReservedAmountNotPassedQty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, divergentQty := range []int64{0, 60, -3} {
		a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
			Balances: map[string]billing.Amount{"ag": mustAmount(t, "10.00", "USD")},
		})
		res, err := a.Authorize(ctx, billing.AuthorizeRequest{
			BillingRef: "ag",
			UnitCost:   mustAmount(t, "0.05", "USD"),
			Quantity:   10, // reserves 0.05 * 10 = 0.50
		})
		if err != nil || !res.Approved {
			t.Fatalf("authorize: approved=%v err=%v", res.Approved, err)
		}
		if err := a.Record(ctx, res.BillingID, divergentQty, ""); err != nil {
			t.Fatalf("record(qty=%d): %v", divergentQty, err)
		}
		bal, _ := a.GetBalance(ctx, "ag")
		// Settled charge is always the reserved 0.50 → balance 9.50.
		want, _ := billing.NewAmount("9.50", "USD")
		if bal.Value.Cmp(want.Value) != 0 {
			t.Errorf("record(qty=%d): balance = %s, want 9.50 (reserved amount, not unitCost*qty)",
				divergentQty, bal.Value.FloatString(4))
		}
	}
}

// TestInMemoryAdapter_ReleaseRestoresQuota verifies: Release
// restores quota decremented at Authorize; Record (success path) does not.
func TestInMemoryAdapter_ReleaseRestoresQuota(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Release restores quota.
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "10.00", "USD")},
		Quotas:   map[string]int64{"ag": 5},
	})
	res, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 3,
	})
	if q, _ := a.GetQuota(ctx, "ag"); q != 2 {
		t.Fatalf("quota after Authorize = %d, want 2", q)
	}
	if err := a.Release(ctx, res.BillingID, ""); err != nil {
		t.Fatalf("release: %v", err)
	}
	if q, _ := a.GetQuota(ctx, "ag"); q != 5 {
		t.Errorf("quota after Release = %d, want 5 (restored)", q)
	}

	// Record (success path) consumes quota: it must NOT be restored.
	res2, _ := a.Authorize(ctx, billing.AuthorizeRequest{
		BillingRef: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 3,
	})
	if err := a.Record(ctx, res2.BillingID, 3, ""); err != nil {
		t.Fatalf("record: %v", err)
	}
	if q, _ := a.GetQuota(ctx, "ag"); q != 2 {
		t.Errorf("quota after Record = %d, want 2 (consumed, not restored)", q)
	}
}

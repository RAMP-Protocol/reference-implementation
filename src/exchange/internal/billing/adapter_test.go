package billing_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

func mustAmount(t *testing.T, raw, currency string) billing.Amount {
	t.Helper()
	a, err := billing.NewAmount(raw, currency)
	if err != nil {
		t.Fatalf("NewAmount: %v", err)
	}
	return a
}

func TestInMemoryAdapter_AuthorizeAndRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag-1": mustAmount(t, "1.00", "USD")},
	})
	res, err := a.Authorize(ctx, billing.AuthorizeRequest{
		TenantID: "t-1", AgentID: "ag-1",
		UnitCost: mustAmount(t, "0.05", "USD"),
		Quantity: 10, Unit: "tokens",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !res.Approved {
		t.Fatalf("expected approval: %s", res.Reason)
	}
	if res.BillingID == "" {
		t.Fatal("billing id empty")
	}
	if err := a.Record(ctx, res.BillingID, 10); err != nil {
		t.Fatalf("record: %v", err)
	}
	bal, _ := a.GetBalance(ctx, "ag-1")
	// 1.00 - 0.05 * 10 = 0.50
	want, _ := billing.NewAmount("0.50", "USD")
	if bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want %s", bal.Value.FloatString(4), want.Value.FloatString(4))
	}
}

func TestInMemoryAdapter_InsufficientBalance(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "0.01", "USD")},
	})
	res, err := a.Authorize(context.Background(), billing.AuthorizeRequest{
		AgentID: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 5,
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
		AgentID: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
	})
	if res.Approved {
		t.Fatal("expected denial on currency mismatch")
	}
}

func TestInMemoryAdapter_UnknownAgent(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{})
	res, _ := a.Authorize(context.Background(), billing.AuthorizeRequest{
		AgentID: "nope", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 1,
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
		AgentID: "ag", UnitCost: mustAmount(t, "0.05", "USD"), Quantity: 2,
	})
	if res.Approved {
		t.Fatal("expected quota denial")
	}
}

func TestInMemoryAdapter_RecordUnknownID(t *testing.T) {
	t.Parallel()
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{})
	err := a.Record(context.Background(), "bogus", 1)
	if !errors.Is(err, billing.ErrUnknownBillingID) {
		t.Fatalf("want ErrUnknownBillingID, got %v", err)
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

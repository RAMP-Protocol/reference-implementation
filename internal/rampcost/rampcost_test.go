package rampcost_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampcost"
)

func item(amount, currency string) *rampv1.TransactionResultItem {
	if currency == "" && amount == "" {
		return &rampv1.TransactionResultItem{}
	}
	return &rampv1.TransactionResultItem{Cost: &rampv1.Cost{Amount: amount, Currency: currency}}
}

// TestBatchTotal pins the per-currency aggregation contract: a single scalar
// only when the whole batch shares one currency, nil for mixed-currency / no
// cost, exact decimal sums, and a hard error on a malformed amount.
func TestBatchTotal(t *testing.T) {
	t.Run("single currency sums exactly", func(t *testing.T) {
		got, err := rampcost.BatchTotal([]*rampv1.TransactionResultItem{
			item("2.5", "USD"), item("5", "USD"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.GetCurrency() != "USD" || got.GetAmount() != "7.5" {
			t.Fatalf("got %v, want amount=7.5 currency=USD", got)
		}
	})

	t.Run("mixed currency drops the scalar", func(t *testing.T) {
		got, err := rampcost.BatchTotal([]*rampv1.TransactionResultItem{
			item("2.5", "USD"), item("3", "EUR"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("got %v, want nil (mixed currency)", got)
		}
	})

	t.Run("no costed items yields nil", func(t *testing.T) {
		got, err := rampcost.BatchTotal([]*rampv1.TransactionResultItem{
			item("", ""), item("0.10", ""), // nil cost, then empty currency
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("got %v, want nil (no costed items)", got)
		}
	})

	t.Run("skips uncosted items between costed ones", func(t *testing.T) {
		got, err := rampcost.BatchTotal([]*rampv1.TransactionResultItem{
			item("1.00", "USD"), item("", ""), item("0.99", "USD"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.GetAmount() != "1.99" {
			t.Fatalf("got %v, want amount=1.99 currency=USD", got)
		}
	})

	t.Run("malformed amount errors", func(t *testing.T) {
		_, err := rampcost.BatchTotal([]*rampv1.TransactionResultItem{
			item("not-a-number", "USD"),
		})
		if err == nil {
			t.Fatal("want error on malformed amount, got nil")
		}
	})
}

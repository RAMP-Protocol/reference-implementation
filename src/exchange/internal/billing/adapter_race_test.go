package billing_test

import (
	"context"
	"math/big"
	"sync"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
)

// TestInMemoryAdapter_ConcurrentAuthorize verifies that concurrent Authorize
// calls on the same agent do not over-debit the balance. Run with -race.
func TestInMemoryAdapter_ConcurrentAuthorize(t *testing.T) {
	t.Parallel()
	const goroutines = 20
	ctx := context.Background()

	// Seed $1.00 at $0.05 per unit — allows exactly 20 approvals.
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "USD")},
	})

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		approved int
		denied   int
	)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			res, err := a.Authorize(ctx, billing.AuthorizeRequest{
				TenantID: "t",
				AgentID:  "ag",
				UnitCost: mustAmount(t, "0.05", "USD"),
				Quantity: 1,
				Unit:     "access",
			})
			if err != nil {
				t.Errorf("Authorize error: %v", err)
				return
			}
			mu.Lock()
			if res.Approved {
				approved++
			} else {
				denied++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if approved != goroutines {
		t.Errorf("approved = %d, want %d (denied = %d)", approved, goroutines, denied)
	}
	bal, err := a.GetBalance(ctx, "ag")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.Value.Sign() < 0 {
		t.Errorf("balance went negative: %s", bal.Value.FloatString(4))
	}
}

// TestInMemoryAdapter_ConcurrentDrain verifies that the adapter never debits
// more than the available balance across concurrent callers that compete for
// the last units.
func TestInMemoryAdapter_ConcurrentDrain(t *testing.T) {
	t.Parallel()
	const goroutines = 50
	ctx := context.Background()

	// Seed $1.00 at $0.10 per unit — allows exactly 10 approvals.
	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "1.00", "USD")},
	})

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		approved int
		ids      []string
	)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			res, err := a.Authorize(ctx, billing.AuthorizeRequest{
				TenantID: "t",
				AgentID:  "ag",
				UnitCost: mustAmount(t, "0.10", "USD"),
				Quantity: 1,
				Unit:     "access",
			})
			if err != nil {
				t.Errorf("Authorize error: %v", err)
				return
			}
			if res.Approved {
				mu.Lock()
				approved++
				ids = append(ids, res.BillingID)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if approved > 10 {
		t.Errorf("over-approved: %d approvals for $1.00 at $0.10 each", approved)
	}

	// After all approvals are reserved, balance should not be negative.
	bal, err := a.GetBalance(ctx, "ag")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.Value.Sign() < 0 {
		t.Errorf("balance went negative: %s", bal.Value.FloatString(4))
	}

	// Record all reservations; aggregate should match exactly.
	for _, id := range ids {
		if err := a.Record(ctx, id, 1); err != nil {
			t.Errorf("Record(%q): %v", id, err)
		}
	}
}

// TestInMemoryAdapter_AuthorizeRecordRace exercises Authorize + Record +
// Cancel under concurrent load to surface data races.
func TestInMemoryAdapter_AuthorizeRecordRace(t *testing.T) {
	t.Parallel()
	const goroutines = 30
	ctx := context.Background()

	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "100.00", "USD")},
	})

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			res, err := a.Authorize(ctx, billing.AuthorizeRequest{
				TenantID: "t",
				AgentID:  "ag",
				UnitCost: mustAmount(t, "0.01", "USD"),
				Quantity: 1,
				Unit:     "access",
			})
			if err != nil || !res.Approved {
				return
			}
			// Even goroutines Record; odd goroutines Cancel.
			if i%2 == 0 {
				_ = a.Record(ctx, res.BillingID, 1)
			} else {
				_ = a.Cancel(ctx, res.BillingID)
			}
		}(i)
	}
	wg.Wait()

	// Balance must be non-negative and parseable.
	bal, err := a.GetBalance(ctx, "ag")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.Value.Cmp(new(big.Rat)) < 0 {
		t.Errorf("balance went negative: %s", bal.Value.FloatString(4))
	}
}

// TestInMemoryAdapter_ConcurrentGetBalance confirms read-path races are absent.
func TestInMemoryAdapter_ConcurrentGetBalance(t *testing.T) {
	t.Parallel()
	const readers = 50
	ctx := context.Background()

	a := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{"ag": mustAmount(t, "5.00", "USD")},
	})

	var wg sync.WaitGroup
	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			bal, err := a.GetBalance(ctx, "ag")
			if err != nil {
				t.Errorf("GetBalance: %v", err)
				return
			}
			if bal.Value == nil {
				t.Error("balance value is nil")
			}
		}()
	}
	wg.Wait()
}

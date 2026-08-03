package transport

// Regression: the Broker budget gate must account money as EXACT fixed-point
// decimal at 8dp (1e8), NOT int64 cents. The old gate did
// int64(amount*100) (resolve.go:409,412; canonical.go:29), which truncated any
// sub-cent amount to 0 — so a $0.005 offer contributed nothing to the consumed
// budget and the period cap could never deplete. User DECISION 1 (decimal, not
// cents; settlement allows fractions of a cent) + DECISION 3 (8dp fixed-point
// int64 so the Redis INCRBY counter stays atomic) define the new behavior these
// tests pin.
//
// TEST LEVEL — narrowest real surface, no infra. The full Resolve RPC budget
// gate needs testcontainers Postgres + Redis (resolve_integration_test.go is
// //go:build integration). Per the task's fallback clause, these drive the gate
// through the REAL budget.MemoryService (the production in-memory Service, usable
// without Redis) plus the new money->fixed-point boundary helper the migration
// adds. MemoryService.Check/Record is the same code the Redis path mirrors; only
// the storage backend differs. No mock of the budget service, no raw state peek
// — Check/Record IS the public budget surface.
//
// EXPECTED RED at the current pin (protocol f4c1e71, pre money-as-string):
// moneyStringToFixedPoint does not yet exist, so this file does not compile.
// That compile failure pins the REQUIREMENT shape (a money-string -> exact 1e8
// fixed-point boundary). The numeric assertions below are written so that a
// NAÏVE 2-decimal-cents implementation (int64(amount*100)) would FAIL them even
// once it compiles: $0.005 -> 0 under cents (budget never depletes, the bug),
// and $0.29 -> 28 under int64(0.29*100) float error instead of the exact 29.

import (
	"context"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/budget"
)

// TestMoneyStringToFixedPoint_ExactSubCent pins the boundary conversion: a
// canonical money string crosses to EXACT 1e8 fixed-point units with no float
// error and no cents truncation.
//
// $0.29 must become exactly 29_000_000 fixed-point units. The old float path
// int64(0.29*100) yields 28 (0.29 has no exact binary float representation), and
// a cents path yields 29 (right value, wrong scale). Only the exact decimal->1e8
// path yields 29_000_000. $0.005 must become 500_000 — a cents path truncates it
// to 0, which is the precise bug this migration exists to kill.
func TestMoneyStringToFixedPoint_ExactSubCent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		money string
		want  int64
	}{
		{"0.29", 29_000_000}, // float-error guard: int64(0.29*100)=28, exact=29 -> *1e8
		{"0.005", 500_000},   // sub-cent guard: cents truncates to 0 (the bug)
		{"0.00000001", 1},    // 8dp floor: one fixed-point unit
		{"5", 500_000_000},   // whole dollars
		{"0.01", 1_000_000},  // one cent in 1e8 units
	}
	for _, tc := range cases {
		got, err := moneyStringToFixedPoint(tc.money)
		if err != nil {
			t.Fatalf("moneyStringToFixedPoint(%q) error: %v", tc.money, err)
		}
		if got != tc.want {
			t.Errorf("moneyStringToFixedPoint(%q) = %d, want %d (8dp fixed-point; cents/float impl is wrong here)",
				tc.money, got, tc.want)
		}
	}
}

// TestBudgetGate_FractionalCentDepletesAndDenies is the load-bearing guard.
// A PeriodBudget of $0.01 and two offers each costing $0.005: after RECORDING
// both through the real budget.Service, the budget is EXACTLY exhausted
// (consumed == limit) and a THIRD $0.005 offer is DENIED by the projected-cost
// gate (projected > limit).
//
// Under the old int64(amount*100) cents model, $0.005 -> 0 fixed units, so
// Record is a no-op (Record guards cost<=0 -> nil), consumed stays 0, the budget
// NEVER depletes, and the third offer is wrongly ALLOWED. This test fails on
// that model and passes only when sub-cent value is accounted exactly at 8dp.
//
// Round-trip honesty: this is a budget-SERVICE round-trip (limit + cost cross
// the money-string boundary into 1e8 fixed-point, are recorded in the real
// MemoryService, and the deny decision is read back through Check + the same
// projected-cost rule the production handler applies). It is NOT a full protocol
// round-trip — the Resolve RPC, discovery, probe, and Exchange execute legs are
// exercised by resolve_integration_test.go, not here.
func TestBudgetGate_FractionalCentDepletesAndDenies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// The budget counter keys on the authenticated agent identity, so
	// this is the agent id, not a billing_ref.
	const agentID = "agent-subcent"
	// $0.01 budget; each offer costs $0.005 — two exactly exhaust it.
	limit := mustFixed(t, "0.01")
	offerCost := mustFixed(t, "0.005")

	svc := budget.NewMemory(clock.System{})

	// Gate replays the production checkBudget rule: deny when the projected
	// consumed (current consumed + this offer) would exceed the limit.
	allowed := func() bool {
		dec, err := svc.Check(ctx, agentID, limit)
		if err != nil {
			t.Fatalf("budget Check: %v", err)
		}
		if !dec.Allowed {
			return false
		}
		return dec.Consumed+offerCost <= dec.Limit
	}

	// Offer #1: budget empty -> allowed; record it.
	if !allowed() {
		t.Fatal("offer #1 ($0.005 against $0.01) must be allowed")
	}
	if err := svc.Record(ctx, agentID, offerCost); err != nil {
		t.Fatalf("record offer #1: %v", err)
	}

	// Offer #2: $0.005 consumed, $0.005 headroom -> allowed; record it.
	if !allowed() {
		t.Fatal("offer #2 ($0.005, $0.005 already consumed) must be allowed")
	}
	if err := svc.Record(ctx, agentID, offerCost); err != nil {
		t.Fatalf("record offer #2: %v", err)
	}

	// Budget is now EXACTLY exhausted. Under cents truncation consumed would
	// still be 0 here (the bug); under 8dp fixed-point it equals the limit.
	dec, err := svc.Check(ctx, agentID, limit)
	if err != nil {
		t.Fatalf("budget Check after two records: %v", err)
	}
	if dec.Consumed != limit {
		t.Errorf("consumed after two $0.005 records = %d, want %d (== $0.01 limit). "+
			"A cents impl truncates $0.005 to 0 and leaves consumed at 0 — the bug.",
			dec.Consumed, limit)
	}

	// Offer #3: projected ($0.015) > limit ($0.01) -> DENIED.
	if allowed() {
		t.Error("offer #3 must be DENIED — $0.01 budget is exhausted by two $0.005 offers. " +
			"Allowing it means sub-cent cost was truncated to 0 (the old int64(amount*100) bug).")
	}
}

func mustFixed(t *testing.T, money string) int64 {
	t.Helper()
	v, err := moneyStringToFixedPoint(money)
	if err != nil {
		t.Fatalf("moneyStringToFixedPoint(%q): %v", money, err)
	}
	return v
}

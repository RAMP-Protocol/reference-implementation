//go:build integration

package transport_test

import (
	"context"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Money source-of-truth split.
//
// The Broker's budget pre-flight (transport.costFixed), ranking
// (selection.unitCost), and audit (candidatesToInfo) MUST all read the SAME
// canonical per-unit charge: Pricing.unit_cost when present, else Pricing.rate.
// That canonical value is exactly what the Exchange bills the agent
// (exchange_helpers.authorizeBilling / exchange_batch.buildBatchResultItem both
// denominate the charge in unit_cost; rate is never read on the charge path). So
// the budget gate must admit/deny against unit_cost — the price the agent will
// actually pay — not against the provider-model rate.
//
// The bug these tests pin: costFixed (resolve.go) reads Pricing.rate ONLY. When
// an offer's normalised unit_cost differs from its provider rate, the gate
// admits/denies against rate while the agent is charged unit_cost. The defect is
// masked in every other suite because the mock Exchange sets rate == unit_cost
// (the catalog_pricing unit_cost<-rate fallback case); these tests force the
// divergence via mockExchange.offerRate.
//
// Round-trip honesty: every leg is a genuine PROTOCOL round-trip — signed Connect
// client -> RFC 9421 httpsig middleware -> registered Broker Resolve handler ->
// resolve core (candidateDomains -> probe -> DiscoverResources against the REAL
// mock Exchange Connect server -> selection -> checkBudget) -> toDiscoveryResponse
// -> typed DiscoveryResponse. The allow/deny decision is observed THROUGH that
// same public Resolve RPC surface: an allowed resolve returns non-empty
// offer_groups (the licensed-discovery signal) with no absence_reason; a denied
// resolve returns empty offer_groups with the typed NOT_AUTHORIZED absence_reason
// (budgetExhaustedResponse). The side effect is asserted at the same surface:
// allowed => the Exchange's DiscoverResources WAS reached (discoverCalls==1) and
// no execute fired; denied => the typed refusal with no retrieval_endpoint.

// TestResolve_BudgetGate_UnitCostBelowLimitBelowRate_Allowed is the load-bearing
// RED case. The offer's unit_cost ($0.05) is BELOW the budget limit ($0.10),
// which is in turn below the provider rate ($0.20):
//
//	unit_cost ($0.05)  <  limit ($0.10)  <  rate ($0.20)
//
// The agent will be billed unit_cost ($0.05), which is UNDER budget, so the
// resolve MUST be ALLOWED. On HEAD costFixed reads rate ($0.20) > limit ($0.10),
// so the budget gate DENIES and the response is the NOT_AUTHORIZED refusal —
// this test FAILS (RED). After costFixed is switched to project
// selection.OfferCharge (unit_cost-else-rate), the gate reads $0.05 <= $0.10 and
// the resolve is allowed (GREEN).
func TestResolve_BudgetGate_UnitCostBelowLimitBelowRate_Allowed(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	// unit_cost = $0.05 (what the agent is actually charged), rate = $0.20 (the
	// provider-model price the buggy gate reads). Limit straddles them at $0.10.
	fx.exchange.offerUnitCost = 0.05
	fx.exchange.offerRate = 0.20
	// Pin estimated_quantity = 1 to isolate the FIELD-SELECTION assertion
	// (unit_cost vs rate) from the quantity multiply. The fixture default is 42,
	// and the budget gate now projects unit_cost * estimated_quantity; the
	// multi-unit projection is covered by TestResolve_BudgetGate_MultiUnitChargeExceedsLimit_Denied.
	fx.exchange.offerEstimatedQuantity = 1

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 10, // $0.10 cap (cents); unit_cost $0.05 < cap < rate $0.20
	})

	// ALLOWED: licensed-discovery returns the ranked offer (non-empty groups),
	// NOT the budget-exhausted refusal. The budget gate must admit against the
	// $0.05 unit_cost the agent will actually pay.
	if got := out.GetAbsenceReason(); got == rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Fatalf("budget gate DENIED an offer whose unit_cost ($0.05) is under the $0.10 limit: "+
			"it read the provider rate ($0.20) instead of the unit_cost the agent is charged. "+
			"absence_reason = %v, want offers returned", got)
	}
	groups := out.GetOfferGroups()
	if len(groups) == 0 || len(groups[0].GetOffers()) == 0 {
		t.Fatalf("expected non-empty offer_groups (resolve must be ALLOWED): groups=%d", len(groups))
	}
	// Side effect at the public surface: discovery WAS reached and the resolve is
	// discovery-only (no execute, no double-billing).
	if srv.exchange.discoverCalls != 1 {
		t.Errorf("discover calls = %d, want 1 (allowed resolve reaches the Exchange)", srv.exchange.discoverCalls)
	}
	if srv.exchange.executeCalls != 0 {
		t.Errorf("execute calls = %d, want 0 (resolve is discovery-only)", srv.exchange.executeCalls)
	}
}

// TestResolve_BudgetGate_RateBelowLimitBelowUnitCost_Denied is the mirror case.
// Now the provider rate ($0.05) is BELOW the limit ($0.10), which is below the
// unit_cost ($0.20):
//
//	rate ($0.05)  <  limit ($0.10)  <  unit_cost ($0.20)
//
// The agent will be billed unit_cost ($0.20), which is OVER budget, so the
// resolve MUST be DENIED (NOT_AUTHORIZED). On HEAD costFixed reads rate ($0.05)
// <= limit ($0.10) and ALLOWS — admitting a transaction the agent cannot afford.
// This asserts the gate denies against the unit_cost the agent actually pays.
func TestResolve_BudgetGate_RateBelowLimitBelowUnitCost_Denied(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	// unit_cost = $0.20 (the charge), rate = $0.05 (the buggy gate's value).
	fx.exchange.offerUnitCost = 0.20
	fx.exchange.offerRate = 0.05
	// Pin estimated_quantity = 1 to isolate field selection from the quantity
	// multiply (fixture default is 42; the gate now projects unit_cost * qty).
	fx.exchange.offerEstimatedQuantity = 1

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 10, // $0.10 cap (cents); rate $0.05 < cap < unit_cost $0.20
	})

	// DENIED: the agent is charged $0.20 unit_cost, over the $0.10 cap, so the
	// gate must refuse with the typed NOT_AUTHORIZED absence_reason.
	if got := out.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Fatalf("budget gate ADMITTED an offer whose unit_cost ($0.20) exceeds the $0.10 limit: "+
			"it read the provider rate ($0.05) instead of the unit_cost the agent is charged. "+
			"absence_reason = %v, want NOT_AUTHORIZED", got)
	}
	if srv.exchange.executeCalls != 0 {
		t.Errorf("budget-denied resolve must not execute: got %d", srv.exchange.executeCalls)
	}
}

// TestResolve_BudgetGate_UnitCostAbsent_ProjectsRate pins the fallback parity:
// when an offer omits unit_cost, the canonical charge falls back to rate — the
// same fallback the Exchange's catalog_pricing applies (unit_cost<-rate) and the
// same fallback selection.unitCost already uses for ranking. With unit_cost
// absent and rate ($0.20) ABOVE the limit ($0.10), the gate must DENY. This case
// stays green on HEAD (costFixed already reads rate); after the fix it stays
// green because OfferCharge falls back to rate when unit_cost is unset — pinning
// that the source-of-truth split does NOT regress the absent-unit_cost path.
func TestResolve_BudgetGate_UnitCostAbsent_ProjectsRate(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	// Leave unit_cost equal to rate via offerRate==0 so the offer's effective
	// charge is rate; set both to $0.20, above the $0.10 cap.
	fx.exchange.offerUnitCost = 0.20
	// Pin estimated_quantity = 1 to isolate the rate-fallback field selection from
	// the quantity multiply (fixture default is 42; the gate now projects unit_cost * qty).
	fx.exchange.offerEstimatedQuantity = 1

	_, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 10, // $0.10 cap (cents) < $0.20 charge
	})

	if got := out.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Fatalf("rate-projected charge ($0.20) exceeds the $0.10 limit but resolve was allowed: "+
			"absence_reason = %v, want NOT_AUTHORIZED", got)
	}
}

// TestResolve_BudgetGate_MultiUnitChargeExceedsLimit_Denied is the multi-unit
// under-projection regression. The discovered
// offer carries a PER-UNIT unit_cost ($0.05) AND an estimated_quantity of 4, so
// the total charge the Exchange will bill is unit_cost * estimated_quantity =
// $0.05 * 4 = $0.20. The agent budget limit is set so that a SINGLE unit is
// affordable but the real multi-unit charge is NOT:
//
//	unit_cost ($0.05)  <  limit ($0.10)  <  unit_cost*qty ($0.20)
//
// The Exchange bills unit_cost * max(estimated_quantity, 1) (exchange_helpers.go
// authorizeBilling / exchange_batch.go), so the broker pre-flight MUST project
// the SAME quantity-multiplied amount and DENY: $0.20 charge exceeds the $0.10
// cap. On HEAD the gate is RED — costFixed projects selection.OfferCharge, which
// returns the PER-UNIT $0.05 with NO * estimated_quantity, so it reads
// $0.05 <= $0.10 and wrongly ADMITS the resolve (non-empty offer_groups, no
// NOT_AUTHORIZED) for a transaction whose actual charge ($0.20) blows the budget.
//
// Round-trip honesty: every leg is a genuine PROTOCOL round-trip — signed Connect
// client -> RFC 9421 httpsig middleware -> registered Broker Resolve handler ->
// resolve core (candidateDomains -> probe -> DiscoverResources against the REAL
// mock Exchange Connect server, whose offer now carries Pricing.estimated_quantity
// -> selection -> checkBudget) -> toDiscoveryResponse -> typed DiscoveryResponse.
// The allow/deny decision is observed THROUGH that same public Resolve RPC: a
// denied resolve returns empty offer_groups with the typed NOT_AUTHORIZED
// absence_reason (budgetExhaustedResponse) and no retrieval_endpoint.
func TestResolve_BudgetGate_MultiUnitChargeExceedsLimit_Denied(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	// unit_cost = $0.05 per unit, estimated_quantity = 4 => the Exchange bills
	// $0.20. A single unit ($0.05) is under the $0.10 cap; the real charge is not.
	fx.exchange.offerUnitCost = 0.05
	fx.exchange.offerEstimatedQuantity = 4

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 10, // $0.10 cap (cents); $0.05 unit < cap < $0.20 total charge
	})

	// DENIED: the Exchange will bill unit_cost * estimated_quantity ($0.20), over
	// the $0.10 cap, so the pre-flight must refuse with the typed NOT_AUTHORIZED
	// absence_reason. On HEAD the gate projects only the per-unit $0.05 and admits.
	if got := out.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_AUTHORIZED {
		t.Fatalf("budget gate ADMITTED a resolve whose multi-unit charge "+
			"(unit_cost $0.05 * estimated_quantity 4 = $0.20) exceeds the $0.10 limit: "+
			"the pre-flight projected only the per-unit $0.05 and never multiplied by "+
			"estimated_quantity. absence_reason = %v, want NOT_AUTHORIZED", got)
	}
	// A budget-denied resolve must surface no offers and mint no retrieval endpoint.
	if groups := out.GetOfferGroups(); len(groups) != 0 {
		t.Errorf("budget-denied resolve must return empty offer_groups, got %d groups", len(groups))
	}
	if srv.exchange.executeCalls != 0 {
		t.Errorf("budget-denied resolve must not execute: got %d", srv.exchange.executeCalls)
	}
}

//go:build integration

package transport_test

import (
	"context"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestResolve_BrokerStatesHowItFoundTheURI pins who decides the discovery method
// an agent receives, and that every group carries one.
//
// The Broker decides it. Only the Broker knows whether the agent named a URI or
// the Broker chose it — the exchange it queries is handed a URI list either way
// and cannot tell those apart. So the Broker states the method from the strategy
// it ran, and whatever the exchange reported is not consulted.
//
// The mock is set to SEARCH, a value this path must never produce, so the
// assertion separates the two possible implementations: carrying the upstream
// value would yield SEARCH, deciding it yields EXCHANGE. Without that the mock
// would report EXCHANGE anyway and a carry-through bug would be invisible.
//
// The batch is mixed on purpose, because the two group shapes reach the response
// by different routes and an agent must be able to read the field off both. The
// first URI routes to the mock Exchange and comes back with offers; the second
// is routed but never answered for, so routePlan.assemble synthesises the
// NOT_IN_CATALOG absence group, which never passes through an exchange at all.
//
// Round-trip: signed Connect client -> RFC 9421 -> httpsig middleware ->
// BrokerService handler -> resolve core -> toDiscoveryResponse -> typed
// DiscoveryResponse. Nothing is read below the RPC.
func TestResolve_BrokerStatesHowItFoundTheURI(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	fx.exchange.discoveryMethod = rampv1.DiscoveryMethod_DISCOVERY_METHOD_SEARCH

	_, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uris: []string{
			"https://acme.example/article-42", // cataloged: the group carries offers
			"https://acme.example/article-99", // not cataloged: typed-absence group
		},
		budgetMinor: 10000,
	})

	groups := out.GetOfferGroups()
	if len(groups) != 2 {
		t.Fatalf("offer_groups = %d, want 2 (one per requested URI)", len(groups))
	}
	// Assert the two shapes are actually distinct before asserting what they
	// share: if both groups drifted to the same shape, the method assertion
	// below would still pass while covering half of what it claims.
	if len(groups[0].GetOffers()) == 0 {
		t.Fatalf("first group carries no offers — wrong fixture state")
	}
	if got := groups[1].GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG {
		t.Fatalf("second group absence_reason = %v, want NOT_IN_CATALOG", got)
	}

	want := rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE
	for i, group := range groups {
		if got := group.GetDiscoveryMethod(); got != want {
			t.Errorf("group %d (%s): discovery_method = %v, want %v — the agent named this URI, "+
				"so the Broker reports %v whatever the exchange said",
				i, group.GetUri(), got, want, want)
		}
	}
}

// TestResolve_QueryOnlyRequestYieldsNoGroups is what the query path does in
// production TODAY, and it is the only query-path claim this file makes about
// production.
//
// ResourceQuery has no free-text field, so the Broker's broadcast path relays a
// query carrying zero URIs, and a compliant Exchange refuses exactly that with
// "at least one uri required". Every routed exchange therefore fails, which is
// the allUpstreamFailed condition, and the batch answers TEMPORARILY_UNAVAILABLE
// with no groups. No agent receives a discovery method on this path at all.
//
// The mock is switched to the compliant behaviour for this test only; it answers
// a URI-less query by default, and sixteen pre-existing query suites depend on
// that. When the work that forwards matched URLs to the Exchange lands, this test
// is the one that must change, and its failure will say so.
func TestResolve_QueryOnlyRequestYieldsNoGroups(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})
	fx.exchange.rejectURILessQuery = true

	_, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		query:       "RAMP intro",
		budgetMinor: 10000,
	})

	if groups := out.GetOfferGroups(); len(groups) != 0 {
		t.Errorf("offer_groups = %d, want 0 — a compliant Exchange refuses the URI-less query "+
			"the broadcast path sends, so no group reaches the agent", len(groups))
	}
	want := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_TEMPORARILY_UNAVAILABLE
	if got := out.GetAbsenceReason(); got != want {
		t.Errorf("absence_reason = %v, want %v — every upstream refused", got, want)
	}
}

// TestResolve_BroadcastGroupsAreStampedSearch pins the Broker's stamping rule for
// the branch it takes when the agent names no URI: whatever that branch returns
// is labelled SEARCH, never EXCHANGE. Swap the constant in discover and this
// fails; that is the regression it guards, and the only one.
//
// It does NOT show the query path working. Reaching the stamp needs an Exchange
// that answers a URI-less query, which no compliant Exchange does — the test
// above is the production behaviour. This one uses the mock's default,
// non-compliant answer purely to get a group in front of the stamping code, so
// treat it as a unit test of that rule wearing an integration test's clothes.
// It is worth keeping because the rule is what makes the future search path
// truthful, and it is cheaper to pin now than to remember later.
func TestResolve_BroadcastGroupsAreStampedSearch(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	_, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		query:       "RAMP intro",
		budgetMinor: 10000,
	})

	groups := out.GetOfferGroups()
	if len(groups) == 0 {
		t.Fatalf("offer_groups is empty — the fixture produced no group to read the stamp off")
	}
	want := rampv1.DiscoveryMethod_DISCOVERY_METHOD_SEARCH
	for i, group := range groups {
		if got := group.GetDiscoveryMethod(); got != want {
			t.Errorf("group %d (%s): discovery_method = %v, want %v — the Broker chose this URI, "+
				"the agent never named it", i, group.GetUri(), got, want)
		}
	}
}

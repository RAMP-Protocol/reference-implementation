//go:build integration

package transport_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestDiscover_EveryGroupCarriesExchangeDiscoveryMethod pins that every
// OfferGroup the Exchange emits says how the resource was found. The Exchange
// answers only out of its own catalog, so the answer is always
// DISCOVERY_METHOD_EXCHANGE — including on the two branches that carry no
// offer, which is where an "only set it on the happy path" implementation
// leaves the field at UNSPECIFIED.
//
// The absent-field case is not a cosmetic gap. The Broker's discover relay
// parses this ResourceResponse and encodes it again, carrying whatever method
// it finds and inventing nothing, so a field missing here is a field the agent
// never sees on that surface. The Broker's Resolve path does not read this
// value at all — it states how IT found the URI — so this RPC is the only place
// the Exchange's own answer is decided.
//
// Round-trip: pushed through the public CatalogService.PushResources surface,
// read back through the public ExchangeService.DiscoverResources surface. No
// DB, no sqlc, no service call — one harness, all three groupFor branches.
func TestDiscover_EveryGroupCarriesExchangeDiscoveryMethod(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	// A term nothing gates: any requester is entitled to it, so discovery
	// yields an offer.
	pushTerms(t, h, client, callerID, "/method/open", scopedTerm("open"))
	// A term gated on a scope the requester does not hold: the entry is in the
	// catalog, but no term survives Select, so there is no priced term and
	// therefore no offer (catalog_scope_integration_test.go pins that
	// behaviour). The group is still returned, bound to its URI.
	pushTerms(t, h, client, callerID, "/method/gated", scopedTerm("gated", "dist:US"))

	cases := []struct {
		name       string
		uri        string
		spec       requesterSpec
		wantOffers int
		wantReason rampv1.OfferAbsenceReason
	}{
		{
			name:       "catalog hit: the group carries an offer",
			uri:        "https://" + h.publisherDom + "/method/open",
			spec:       requesterWithScopes("agent-method-open"),
			wantOffers: 1,
		},
		{
			name:       "catalog hit, no eligible priced term: the group is present and empty",
			uri:        "https://" + h.publisherDom + "/method/gated",
			spec:       requesterWithScopes("agent-method-gated"),
			wantOffers: 0,
		},
		{
			name:       "catalog miss: the group carries the typed absence reason",
			uri:        "https://" + h.publisherDom + "/method/never-pushed",
			spec:       requesterWithScopes("agent-method-miss"),
			wantOffers: 0,
			wantReason: rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			groups := discoverAs(t, h, tc.uri, tc.spec).GetOfferGroups()
			if len(groups) != 1 {
				t.Fatalf("offer_groups = %d, want 1 (one requested URI)", len(groups))
			}
			group := groups[0]
			// Assert the branch first: a case that silently stopped exercising
			// the branch it names would still pass the method assertion.
			if got := len(group.GetOffers()); got != tc.wantOffers {
				t.Fatalf("offers = %d, want %d — wrong branch of groupFor", got, tc.wantOffers)
			}
			if got := group.GetAbsenceReason(); got != tc.wantReason {
				t.Fatalf("absence_reason = %v, want %v", got, tc.wantReason)
			}
			want := rampv1.DiscoveryMethod_DISCOVERY_METHOD_EXCHANGE
			if got := group.GetDiscoveryMethod(); got != want {
				t.Errorf("discovery_method = %v, want %v", got, want)
			}
		})
	}
}

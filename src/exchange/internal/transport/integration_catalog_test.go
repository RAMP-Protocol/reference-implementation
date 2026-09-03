//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// The Agent→Exchange catalog round-trip, in one place: push a resource through
// PushResources, discover it through DiscoverResources, hand back the offer.
// Every suite that needs an offer to execute against starts here, so it arranges
// its state through the same public surface an agent uses and never reaches past
// a layer (Testing Doctrine §9).
//
// Each helper is the general form plus a thin wrapper that supplies the harness
// tenant. A suite that needs a different tenant or a bare URI calls the general
// form; it does not write a second round-trip.

// discoverURI discovers the offers for one absolute URI. Every discovery in the
// package goes through here.
//
// The query carries no Id: ResourceQuery.Id was removed in the WBA-split proto.
// That is the kind of change this single call site exists to absorb — a second
// copy of the request would still be building the old shape.
func discoverURI(t *testing.T, h *testHarness, uri string) []*rampv1.Offer {
	t.Helper()
	resp, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(
		newResourceQuery(newRequester("agent-test", "agent.example"), []string{uri})))
	if err != nil {
		t.Fatalf("discover %s: %v", uri, err)
	}
	if len(resp.Msg.GetOffers()) == 0 {
		t.Fatalf("no offers returned for %s", uri)
	}
	return resp.Msg.GetOffers()
}

// discoverOffer discovers one URI and returns its first signed offer, which is
// what a caller executing against a specific resource wants.
func discoverOffer(t *testing.T, h *testHarness, uri string) *rampv1.Offer {
	t.Helper()
	return discoverURI(t, h, uri)[0]
}

// discoverPath discovers the offers for a single path under the harness tenant.
func discoverPath(t *testing.T, h *testHarness, path string) []*rampv1.Offer {
	t.Helper()
	return discoverURI(t, h, "https://"+h.tenantDomain+path)
}

// discoverFirst discovers the offers for the default seeded path.
func discoverFirst(t *testing.T, h *testHarness) []*rampv1.Offer {
	t.Helper()
	return discoverPath(t, h, "/articles/hello")
}

// pushDiscoverTermOfferForTenant pushes a single-entry catalog at domain+path
// carrying term, under an arbitrary tenant, and returns the first discovered
// offer.
//
// The tenant is a parameter because the reporting gate is keyed on
// (tenant, agent): proving that a denial for one tenant leaves another tenant's
// item alone needs an offer that resolves somewhere other than the harness
// tenant. That is one argument, not a second round-trip.
func pushDiscoverTermOfferForTenant(
	t *testing.T, h *testHarness, tenantID, domain, path string, term *rampv1.LicenseTerm,
) *rampv1.Offer {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(
		newPushRequest(tenantID, "agent-test", []*rampv1.ResourceEntry{{
			Domain: domain,
			Path:   path,
			Terms:  []*rampv1.LicenseTerm{term},
		}})))
	if err != nil {
		t.Fatalf("push %s%s: %v", domain, path, err)
	}
	return discoverURI(t, h, "https://"+domain+path)[0]
}

// pushDiscoverTermOffer pushes a single-entry catalog at path carrying term
// under the harness tenant, discovers it, and returns the first offer. The
// priced and free-resource suites both reuse it, so a PER_UNIT term and a FREE
// term exercise the identical public path.
func pushDiscoverTermOffer(t *testing.T, h *testHarness, path string, term *rampv1.LicenseTerm) *rampv1.Offer {
	t.Helper()
	return pushDiscoverTermOfferForTenant(t, h, h.tenantID, h.tenantDomain, path, term)
}

// pushDiscoverOffer pushes a catalog entry under the harness tenant with the
// given EstimatedQuantity, discovers it, and returns the first offer. Pricing —
// including estimated_quantity, which drives the obligation tolerance window —
// is term-derived.
func pushDiscoverOffer(t *testing.T, h *testHarness, estimatedQty int32) *rampv1.Offer {
	t.Helper()
	return pushDiscoverTermOffer(t, h, "/articles/hello", seedPricedTermEst(estimatedQty))
}

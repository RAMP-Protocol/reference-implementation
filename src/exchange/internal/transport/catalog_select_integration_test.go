//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/proto"
)

// This file owns the SHARED arrange/observe helpers the licensing integration
// suite builds on (pushTerms, selectPricing, userTypeTerm, discoverAs,
// discoverOffersAs, discoverTermsAs, requesterWithExt, labels). discoverAs is
// the RPC entry point: the offer-shaped and group-shaped helpers all read their
// result off it. The requester-attribute Select
// scenarios that once lived here were removed with ADR-014's 2026-06-15
// amendment: the Exchange no longer excludes a term by the requester's
// self-declared user_type / geography / intended_use, so those exclusion
// assertions no longer describe real behaviour. Scope-only projection is pinned
// by catalog_scope_integration_test.go; restrictions ride on the returned offer
// for the agent to self-honour. The helpers stay because the kept scope /
// pricing / cardinality / canonical-feed / ingest tests depend on them.

// pushTerms pushes a single resource entry carrying one or more license terms
// and asserts the push was accepted. It is the multi-term arrange step the
// kept scenarios build on (pushOneTerm covers the single-term case).
func pushTerms(t *testing.T, h *pushHarness, client rampconnect.CatalogServiceClient, callerID, path string, terms ...*rampv1.LicenseTerm) {
	t.Helper()
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom,
			Path:   path,
			Terms:  terms,
		}},
	}))
	if err != nil {
		t.Fatalf("push %s: %v", path, err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("push %s: accepted=%d rejected=%d, want 1/0", path, resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}
}

// selectPricing is the minimal valid Pricing every term needs to clear Validate
// AND the protovalidate interceptor (PER_UNIT⇒unit) and reach the
// catalog. The projection assertions are about which terms project, never about
// the price, so one shared shape suffices.
func selectPricing() *rampv1.Pricing {
	return &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD", Unit: proto.String("accesses")}
}

// userTypeTerm builds an ENUMERATED term carrying a single-token USER_TYPE
// restriction. Post-ADR-014 the restriction no longer gates discovery (it rides
// on the offer for the agent to self-honour); the helper survives because the
// pricing tests use it to assert a restricted term still projects and prices
// normally. partLabel lets assertions identify which term projected without
// depending on field order.
func userTypeTerm(label, userType string) *rampv1.LicenseTerm {
	l := label
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing:   selectPricing(),
		PartLabel: &l,
		Restrictions: []*rampv1.Restriction{{
			Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
			Permitted: []string{userType},
		}},
	}
}

// discoverAs runs DiscoverResources for uri as the given requester and returns
// the whole response. It is the RPC entry point for the licensing helper family:
// discoverOffersAs and discoverTermsAs here, discoverOffers and
// discoverOfferCount in the term-validation file, and discoverCompOffer for the
// profile-aware CoMP reads, which set spec.profiles rather than rebuilding the
// query. The group-shaped reads call it directly. None of them reaches past the
// public surface.
//
// Its signature bounds what can route through it: one uri, and a failed test on
// any error. A caller that discovers a batch, or that asserts on the error
// itself, issues its own request — this helper makes no claim about those.
func discoverAs(t *testing.T, h *pushHarness, uri string, spec requesterSpec) *rampv1.ResourceResponse {
	t.Helper()
	resp, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:                    "1.0",
		Uris:                   []string{uri},
		Requester:              spec.requester,
		AcceptableRestrictions: spec.restrictions,
		SupportedProfiles:      spec.profiles,
	}))
	if err != nil {
		t.Fatalf("discover %s: %v", uri, err)
	}
	return resp.Msg
}

// discoverOffersAs reads the offers DiscoverResources projects for uri to the
// given requester. Every projection assertion drives the FULL application chain
// through this public RPC, never by calling licenseterm.Select with hand-built
// structs.
func discoverOffersAs(t *testing.T, h *pushHarness, uri string, spec requesterSpec) []*rampv1.Offer {
	t.Helper()
	return discoverAs(t, h, uri, spec).GetOffers()
}

// discoverTermsAs returns the terms on the single offer DiscoverResources
// projects for uri to the requester spec.
func discoverTermsAs(t *testing.T, h *pushHarness, uri string, spec requesterSpec) []*rampv1.LicenseTerm {
	t.Helper()
	offers := discoverOffersAs(t, h, uri, spec)
	if len(offers) != 1 {
		t.Fatalf("discover %s: offers = %d, want 1", uri, len(offers))
	}
	return offers[0].GetTerms()
}

// requesterSpec bundles the identity-only Requester with the advisory,
// query-level AcceptableRestrictions it volunteers. After the Universal
// Licensing Core overhaul the requester carries no uris / restrictions; uris and
// the user_type / geography / intended_use facets are query-level data. The
// facets are typed AcceptableRestriction values on the ResourceQuery; the
// Exchange ignores them for projection (ADR-014, scope-only Select), so they are
// retained as harmless no-ops that let the kept tests still exercise requesters
// which declare facets.
type requesterSpec struct {
	requester    *rampv1.Requester
	restrictions []*rampv1.AcceptableRestriction
	// profiles are the ResourceQuery.supported_profiles the caller advertises.
	// Nil for the plain licensing suites; the CoMP helpers set "ramp-comp-v1" so
	// the Exchange is asked to project that profile.
	profiles []string
}

// requesterWithExt builds an identity requester plus the advisory
// user_type / geography / intended_use restrictions it declares. Empty values
// are omitted.
func requesterWithExt(id, userType, geography string, intendedUse ...string) requesterSpec {
	r := &rampv1.Requester{
		Id:     id,
		Domain: "agent.example",
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	var rs []*rampv1.AcceptableRestriction
	if userType != "" {
		rs = append(rs, &rampv1.AcceptableRestriction{
			Axis:   rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
			Values: []string{userType},
		})
	}
	if geography != "" {
		rs = append(rs, &rampv1.AcceptableRestriction{
			Axis:   rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
			Values: []string{geography},
		})
	}
	if len(intendedUse) > 0 {
		rs = append(rs, &rampv1.AcceptableRestriction{
			Axis:   rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
			Values: intendedUse,
		})
	}
	return requesterSpec{requester: r, restrictions: rs}
}

// labels collects the part_label of each term, the order-independent identity
// used to assert which terms projected.
func labels(terms []*rampv1.LicenseTerm) []string {
	out := make([]string, 0, len(terms))
	for _, t := range terms {
		out = append(out, t.GetPartLabel())
	}
	return out
}

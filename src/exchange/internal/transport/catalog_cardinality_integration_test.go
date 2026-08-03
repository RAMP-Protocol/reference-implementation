//go:build integration

package transport_test

import (
	"fmt"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// This file pins the CARDINALITY boundaries the rest of the licensing suite
// leaves implicit — the empty-set ("too small") and large-set ("too big")
// extremes of every collection the push→store→Select→project chain touches.
// Like its siblings it drives behavior exclusively through the public
// PushResources / DiscoverResources RPCs and observes only what those surfaces
// expose (Testing Doctrine pt 9): no DB/repo/sqlc access.

// ---------------------------------------------------------------------------
// TOO SMALL — empty / degenerate input sets.
// ---------------------------------------------------------------------------

// TestPushResources_EmptyBatchRejectedInvalidArgument pins the zero-entry
// boundary: the proto puts no min_items on PushResourcesRequest.entries, so the
// empty batch is structurally valid and reaches the handler — where the service
// guards it. An empty push is a meaningless request, so the handler fails fast
// with InvalidArgument ("entries required") rather than silently returning a
// 0/0 success. This is the lower bound of the batch-partition path, and the test
// pins the guard so a future refactor cannot regress it into a silent no-op.
func TestPushResources_EmptyBatchRejectedInvalidArgument(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	_, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries:  nil,
	}))
	assertConnectCode(t, err, connect.CodeInvalidArgument)
}

// (TestDiscover_EmptyRestrictionTokensBehaveAsAnyAxis was removed with ADR-014's
// 2026-06-15 amendment. It exercised the critical/empty-token fail-closed
// EXCLUSION of a requester that left a restriction axis unevaluable — a
// requester-attribute filter the Exchange no longer applies. The empty-token
// permitted∩prohibited VALIDATION boundary it also touched is owned by
// catalog_validate_terms_integration_test.go, which is unaffected.)

// ---------------------------------------------------------------------------
// TOO BIG — large term lists, large token sets, full-breadth axes, big batches.
// ---------------------------------------------------------------------------

// TestDiscover_ManyTermsProjectInOrderHeadlinePriceFirst pins the large-terms[]
// boundary: one resource carrying many public terms projects ALL of them onto a
// SINGLE offer, in push order, and the offer's headline price is the FIRST
// term's price (D2 — the publisher controls the headline by term order)
// even at scale. Rates are integer-valued floats so the JSONB round-trip is
// exact and the headline assertion needs no tolerance.
func TestDiscover_ManyTermsProjectInOrderHeadlinePriceFirst(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const n = 25
	terms := make([]*rampv1.LicenseTerm, 0, n)
	wantLabels := make([]string, 0, n)
	for i := range n {
		label := fmt.Sprintf("term-%02d", i)
		wantLabels = append(wantLabels, label)
		l := label
		terms = append(terms, &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			PartLabel: &l,
			Pricing: &rampv1.Pricing{
				Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
				Rate:     money(t, float64(i+1)), // first term's rate is "1"
				Currency: "USD",
				Unit:     proto.String("accesses"),
			},
			// no restrictions, no scopes → public → projects for any requester.
		})
	}

	const path = "/cardinality/many-terms"
	uri := "https://" + h.publisherDom + path
	pushTerms(t, h, client, callerID, path, terms...)

	bare := requesterWithExt("agent-bare", "", "")
	offers := discoverOffersAs(t, h, uri, bare)
	if len(offers) != 1 {
		t.Fatalf("offers = %d, want 1 (all %d terms ride one offer)", len(offers), n)
	}
	assertStrs(t, "many terms, order preserved", labels(offers[0].GetTerms()), wantLabels)
	if rate := offers[0].GetPricing().GetRate(); rate != money(t, 1.0) {
		t.Fatalf("headline rate = %v, want %q (first term's price)", rate, money(t, 1.0))
	}
}

// TestDiscover_LargeGeographyTokenSets pins the large permitted[]/prohibited[]
// boundary on a single axis as a STORED-and-RETURNED round-trip. A GEOGRAPHY
// restriction with a 60-token permitted set and a 60-token prohibited set must
// survive Normalize (upper-casing every token at scale), the JSONB column
// round-trip, and the DiscoverResources→Offer.terms projection intact — every
// token comes back, in order, on the returned offer. Post-ADR-014 the Exchange
// no longer EXCLUDES a requester by geography (restrictions ride on the offer
// for the agent to self-honour), so this test asserts the large token sets are
// carried back faithfully rather than used to filter; the requester is a bare
// agent and still receives the term.
func TestDiscover_LargeGeographyTokenSets(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const size = 60
	permitted := make([]string, 0, size)
	prohibited := make([]string, 0, size)
	for i := range size {
		permitted = append(permitted, fmt.Sprintf("GP%02d", i))
		prohibited = append(prohibited, fmt.Sprintf("GX%02d", i))
	}

	label := "large-geo"
	term := &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing:   selectPricing(),
		PartLabel: &label,
		Restrictions: []*rampv1.Restriction{{
			Kind:       rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
			Permitted:  permitted,
			Prohibited: prohibited,
			// non-critical: unregistered synthetic geos are lint warnings,
			// not rejects, so the push is accepted.
		}},
	}

	const path = "/cardinality/geo-large"
	uri := "https://" + h.publisherDom + path
	pushTerms(t, h, client, callerID, path, term)

	// A bare requester discovers the term (no requester-attribute exclusion); the
	// large token sets must come back on the returned offer, upper-cased and in
	// order — the 60-element JSONB round-trip at scale.
	got := discoverTermsAs(t, h, uri, requesterWithExt("agent-bare", "", ""))
	assertStrs(t, "large-geo term returned", labels(got), []string{"large-geo"})

	if n := len(got[0].GetRestrictions()); n != 1 {
		t.Fatalf("returned restrictions = %d, want 1 (the single GEOGRAPHY axis)", n)
	}
	r := got[0].GetRestrictions()[0]
	assertStrs(t, "60 permitted geos round-trip", r.GetPermitted(), permitted)
	assertStrs(t, "60 prohibited geos round-trip", r.GetProhibited(), prohibited)
}

// (TestDiscover_MultiAxisRestrictionsAndCombine was removed with ADR-014's
// 2026-06-15 amendment. It asserted that a term restricted on FUNCTION +
// USER_TYPE + GEOGRAPHY at once EXCLUDED any requester failing one axis — the
// requester-attribute AND-combine filter the Exchange no longer applies. The
// validated maximum of one restriction per kind is still enforced at push by
// catalog_validate_terms_integration_test.go.)

// TestPushResources_LargeBatchAllAcceptedAndDiscoverable pins the large-batch
// boundary: a single PushResources carrying many valid entries accepts every one
// and, after the contributor snapshot rebuilds, each pushed URI resolves to
// exactly one offer. Sampling first/middle/last is enough to prove the whole
// batch landed without re-querying all N.
func TestPushResources_LargeBatchAllAcceptedAndDiscoverable(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const n = 40
	entries := make([]*rampv1.ResourceEntry, 0, n)
	paths := make([]string, 0, n)
	for i := range n {
		path := fmt.Sprintf("/cardinality/batch/item-%02d", i)
		paths = append(paths, path)
		entries = append(entries, &rampv1.ResourceEntry{
			Domain: h.publisherDom,
			Path:   path,
			Terms:  []*rampv1.LicenseTerm{seedPricedTerm()},
		})
	}

	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries:  entries,
	}))
	if err != nil {
		t.Fatalf("large batch push: %v", err)
	}
	if resp.Msg.GetAccepted() != n || resp.Msg.GetRejected() != 0 {
		t.Fatalf("accepted=%d rejected=%d, want %d/0", resp.Msg.GetAccepted(), resp.Msg.GetRejected(), n)
	}

	for _, i := range []int{0, n / 2, n - 1} {
		uri := "https://" + h.publisherDom + paths[i]
		if got := discoverOfferCount(t, h, uri); got != 1 {
			t.Fatalf("batch item %d (%s): offers = %d, want 1 (snapshot must include whole batch)", i, paths[i], got)
		}
	}
}

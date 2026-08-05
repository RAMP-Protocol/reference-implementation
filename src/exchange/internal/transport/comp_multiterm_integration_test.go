//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/comptest"
)

// TestComp_MultitermTermIndex is the multiterm term-index RED baseline: it pins the
// "one offer = one term = one CoMP package" invariant under scope-gated
// multi-term resources, observed END-TO-END through DiscoverResources only (no
// DB / internal-state access — Testing Doctrine pt 9). Every leg pushes terms
// via CatalogService.PushResources and reads back the rendered comp package
// through the public discovery RPC, asserting that comp.id carries the SELECTED
// headline term's ORIGINAL stored publisher index (matrix Q8:
// "<resource_id>#<term-index>") and that comp.scope pricing reflects that same
// headline term.
//
// Two terms ride on each resource in a fixed publisher (stored) order; the
// requester's scopes drive which subset licenseterm.Select keeps; the headline
// is the FIRST eligible term in stored order. The headline's
// ORIGINAL stored index — not a per-offer ordinal, never a hardcoded 0 — must
// appear in comp.id.
//
// It FAILS on current HEAD: comp_render.go hardcodes the package term-index to
// literal 0 (applyCompProfile passes 0 to renderCompProfile), so comp.id is
// ALWAYS "<offer>#0". LEG 1 selects a headline stored at index 1, so HEAD emits
// "<offer>#0" where the matrix requires "<offer>#1" — an assertion failure, not
// a compile/collection error (every RPC and field it uses already exists).
//
// Per the slice's RESOLUTION the headline rule (D2, headline = first
// eligible term in stored order) and the one-offer-per-discovery model are kept
// unchanged; the genuine RED is purely the comp.id term-index. LEG 3 PINS that
// the term-index fix does NOT alter D2 and introduces no new cross-term bleed.
func TestComp_MultitermTermIndex(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	client := h.signedCat(callerID, priv)

	const premiumScope = "subscription:premium"

	// LEG 1 — PRIMARY RED (term-index #1). Resource stored
	// [PREMIUM(index 0, scopes=[subscription:premium], $0.50),
	//  PUBLIC(index 1, empty scopes, $0.05)]. A DEFAULT requester (no scopes)
	// WITH SupportedProfiles=[ramp-comp-v1]: Select drops PREMIUM (uncovered),
	// keeps PUBLIC -> headline = PUBLIC at its ORIGINAL stored index 1.
	//
	// Round-trip: write goes RPC(PushResources)->service->repo->DB; read goes
	// RPC(DiscoverResources)->service->Select->comp render->RPC response, then
	// the parity leg re-drives RPC(ExecuteTransaction)->verifyOffer->Select->
	// comp render. Both legs traverse the full protocol surface; no leg observes
	// state past a layer.
	//
	// HEAD emits comp.id "<offer>#0" (hardcoded), but the headline's original
	// stored index is 1 -> RED on comp.id. comp.scope.unitprice == 0.05 is
	// correct on HEAD (pricing already derives from the PUBLIC headline term).
	t.Run("primary_red_public_headline_stored_index_1", func(t *testing.T) {
		const path = "/articles/comp-premium-first"
		premium := premiumPricedTerm(premiumScope, 0.50)
		public := seedPricedTerm() // empty scopes, PER_UNIT $0.05
		pushTerms(t, h, client, callerID, path, premium, public)

		uri := "https://" + h.publisherDom + path
		// DEFAULT requester: discoverCompOffer sends no requester scopes.
		offer := discoverCompOffer(t, h, uri)

		// Headline = PUBLIC at ORIGINAL stored index 1 -> comp.id "<offer>#1".
		assertCompHeadline(t, offer, 1, 0.05)
		assertTransactParity(t, h, offer)
	})

	// LEG 2 — premium headline (#0). SAME storage order as LEG 1
	// [PREMIUM(0), PUBLIC(1)]. A PREMIUM requester (scopes=[subscription:premium])
	// WITH the profile: Select keeps BOTH in stored order -> headline = PREMIUM
	// at its ORIGINAL stored index 0. comp.scope.unitprice == 0.50 (premium) AND
	// comp.id == "<offer>#0". offer.GetTerms() still carries BOTH eligible terms
	// (non-loss).
	t.Run("premium_headline_stored_index_0", func(t *testing.T) {
		const path = "/articles/comp-premium-first-prem-req"
		premium := premiumPricedTerm(premiumScope, 0.50)
		public := seedPricedTerm()
		pushTerms(t, h, client, callerID, path, premium, public)

		uri := "https://" + h.publisherDom + path
		offer := discoverCompOffer(t, h, uri, premiumScope)

		// Headline = PREMIUM at ORIGINAL stored index 0 -> comp.id "<offer>#0",
		// premium price $0.50.
		assertCompHeadline(t, offer, 0, 0.50)
		// Non-loss: both eligible terms ride on the canonical Offer.terms[].
		if got := len(offer.GetTerms()); got != 2 {
			t.Errorf("offer.terms count = %d, want 2 (both eligible terms ride on the offer)", got)
		}
		assertTransactParityScoped(t, h, offer, premiumScope)
	})

	// LEG 3 — D2 bleed guard (public stored first). Resource stored
	// [PUBLIC(index 0, empty scopes, $0.05),
	//  PREMIUM(index 1, scopes=[subscription:premium], $0.50)]. A PREMIUM
	// requester: Select keeps BOTH in stored order -> headline = PUBLIC (the
	// stored-first eligible term) at its ORIGINAL stored index 0.
	//
	// This PINS that the term-index fix does NOT change D2 and that there is no
	// NEW cross-term bleed: comp reflects the D2 headline (PUBLIC), not the
	// premium sibling the requester also unlocked. comp.scope.unitprice == 0.05
	// (public) AND comp.id == "<offer>#0" (public at stored index 0). Correct on
	// HEAD already (headline index 0); guards the GREEN change against regressing
	// D2.
	t.Run("d2_bleed_guard_public_stored_first", func(t *testing.T) {
		const path = "/articles/comp-public-first"
		public := seedPricedTerm() // stored index 0
		premium := premiumPricedTerm(premiumScope, 0.50)
		pushTerms(t, h, client, callerID, path, public, premium)

		uri := "https://" + h.publisherDom + path
		offer := discoverCompOffer(t, h, uri, premiumScope)

		// Headline = PUBLIC (stored first) at stored index 0 ->
		// comp.id "<offer>#0", public price $0.05.
		assertCompHeadline(t, offer, 0, 0.05)
		assertTransactParityScoped(t, h, offer, premiumScope)
	})
}

// premiumPricedTerm builds a scope-gated ENUMERATED term carrying the given
// entitlement scope and a DISTINCT PER_UNIT rate (so the premium headline's
// comp pricing is observably different from the public term's $0.05). It reuses
// the shared scopedTerm builder (single home for scope-gated terms) and only
// overrides the rate — keeping one term-construction path (jscpd=0) while making
// the price discriminating for the headline assertions.
func premiumPricedTerm(scope string, rate float64) *rampv1.LicenseTerm {
	term := scopedTerm("premium", scope)
	// Rate crosses the wire as a canonical decimal STRING (exact-decimal money
	// spine), not a float64. Render the test's float rate through the spine's
	// FormatMoney so the term carries the same canonical form the production
	// ingest/sign path emits.
	wire, err := helpers.FormatMoney(decimal.NewFromFloat(rate))
	if err != nil {
		panic("premiumPricedTerm: format rate: " + err.Error())
	}
	term.GetPricing().Rate = wire
	return term
}

// assertCompHeadline verifies the single comp package the profile-aware discover
// emitted reflects the SELECTED headline term: comp.id == "<offer>#<wantIndex>"
// (the headline's ORIGINAL stored publisher index, matrix Q8) and
// comp.scope.unitprice == wantRate (the headline term's price). It also asserts
// the emitted comp Struct passes comptest.Validate (a real CoMP parser accepts
// it). The resource id in comp.id is the Offer's own id (tenant-scoped
// composite), so the expectation derives from offer.OfferId.
func assertCompHeadline(t *testing.T, o *rampv1.Offer, wantIndex int, wantRate float64) {
	t.Helper()
	compVal, ok := o.GetExt().GetFields()["comp"]
	if !ok || compVal == nil {
		t.Fatalf("offer.ext has no %q key under ramp-comp-v1: ext=%v", "comp", o.GetExt())
	}
	comp := compVal.GetStructValue()
	if comp == nil {
		t.Fatalf("offer.ext[comp] is not a Struct: %v", compVal)
	}
	fields := comp.GetFields()

	wantID := o.GetOfferId() + "#" + strconv.Itoa(wantIndex)
	if got := fields["id"].GetStringValue(); got != wantID {
		t.Errorf("comp.id = %q, want %q (selected headline's ORIGINAL stored index, matrix Q8)", got, wantID)
	}

	scope := fields["scope"].GetStructValue()
	if scope == nil {
		t.Fatalf("comp.scope missing or not a Struct: %v", fields["scope"])
	}
	if got := scope.GetFields()["unitprice"].GetNumberValue(); got != wantRate {
		t.Errorf("comp.scope.unitprice = %v, want %v (selected headline term's price)", got, wantRate)
	}

	if err := comptest.Validate(comp); err != nil {
		t.Errorf("comptest.Validate(offer.ext[comp]) = %v, want nil", err)
	}
}

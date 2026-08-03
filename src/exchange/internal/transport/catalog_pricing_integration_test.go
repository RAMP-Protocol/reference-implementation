//go:build integration

package transport_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/vocab/pricingunits"
)

// pricedTerm builds an unrestricted PER_UNIT term carrying the given pricing so
// it projects for any requester. partLabel identifies the term in assertions.
func pricedTerm(label, unit, rate string) *rampv1.LicenseTerm {
	l := label
	u := unit
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		PartLabel: &l,
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
			Rate:     rate,
			Currency: "USD",
			Unit:     &u,
		},
	}
}

// flatTerm builds an unrestricted FLAT-priced term: a flat fee (rate) in USD
// with NO metering unit, so it projects for any requester. FLAT carries no unit
// by invariant (mapper.go), which the round-trip below asserts. The rate is
// integer-valued so the float assertion is exact (epic Design pt5).
func flatTerm(label, rate string) *rampv1.LicenseTerm {
	l := label
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		PartLabel: &l,
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel_PRICING_MODEL_FLAT,
			Rate:     rate,
			Currency: "USD",
		},
	}
}

// TestDiscover_FlatPricingRoundTrip proves PRICING_MODEL_FLAT survives the full
// push→store→Select→project chain: a publisher pushes a FLAT term and the
// discovered Offer.pricing reports model=FLAT, the flat fee as the rate, the
// currency preserved, and an EMPTY unit (the FLAT no-unit invariant — a flat fee
// is not metered per unit). Before this, FLAT was only ever parsed in a unit
// test and never round-tripped through the public surface.
func TestDiscover_FlatPricingRoundTrip(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const path = "/pricing/flat"
	uri := "https://" + h.publisherDom + path
	wantRate := money(t, 5.0) // canonical wire form of 5.0 is "5"
	pushTerms(t, h, client, callerID, path, flatTerm("flat", wantRate))

	offers := discoverOffers(t, h, uri)
	if len(offers) != 1 {
		t.Fatalf("offers = %d, want 1", len(offers))
	}
	p := offers[0].GetPricing()
	if p == nil {
		t.Fatal("offer has no pricing")
	}
	if p.GetModel() != rampv1.PricingModel_PRICING_MODEL_FLAT {
		t.Errorf("model = %v, want FLAT", p.GetModel())
	}
	if p.GetRate() != wantRate {
		t.Errorf("rate = %v, want %v (flat fee)", p.GetRate(), wantRate)
	}
	if p.GetCurrency() != "USD" {
		t.Errorf("currency = %q, want USD", p.GetCurrency())
	}
	if p.GetUnit() != "" {
		t.Errorf("unit = %q, want empty (FLAT no-unit invariant)", p.GetUnit())
	}
}

// TestDiscover_PricingDerivedFromTerm proves the term-derived-pricing core invariant through the
// public surface: a publisher pushes a PER_UNIT unit=accesses rate=0.07 term and
// the discovered Offer.pricing reflects THAT term's model/rate/currency/unit — not
// the retired $0.05 defaultPricing stub. The rate 0.07 is deliberately != 0.05 so
// a regression that re-introduced the stub would fail this assertion.
func TestDiscover_PricingDerivedFromTerm(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const path = "/pricing/per-unit"
	uri := "https://" + h.publisherDom + path
	wantRate := money(t, 0.07)
	pushTerms(t, h, client, callerID, path, pricedTerm("priced", pricingunits.Accesses, wantRate))

	offers := discoverOffers(t, h, uri)
	if len(offers) != 1 {
		t.Fatalf("offers = %d, want 1", len(offers))
	}
	p := offers[0].GetPricing()
	if p == nil {
		t.Fatal("offer has no pricing")
	}
	if p.GetModel() != rampv1.PricingModel_PRICING_MODEL_PER_UNIT {
		t.Errorf("model = %v, want PER_UNIT", p.GetModel())
	}
	if p.GetRate() != wantRate {
		t.Errorf("rate = %v, want %v (must derive from the term, not the $0.05 stub)", p.GetRate(), wantRate)
	}
	if p.GetCurrency() != "USD" {
		t.Errorf("currency = %q, want USD", p.GetCurrency())
	}
	if p.GetUnit() != pricingunits.Accesses {
		t.Errorf("unit = %q, want %q", p.GetUnit(), pricingunits.Accesses)
	}
}

// TestDiscover_MultiTermHeadlineIsFirstProjected pins the documented multi-term
// pricing decision: when several eligible terms project, the
// top-level Offer.pricing is the Pricing of the FIRST projected term (publisher
// order). The publisher controls the headline by ordering its terms.
func TestDiscover_MultiTermHeadlineIsFirstProjected(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const path = "/pricing/multi"
	uri := "https://" + h.publisherDom + path
	firstRate, secondRate := money(t, 0.09), money(t, 0.03)
	pushTerms(
		t, h, client, callerID, path,
		pricedTerm("first", pricingunits.Accesses, firstRate),
		pricedTerm("second", pricingunits.Accesses, secondRate),
	)

	offers := discoverOffers(t, h, uri)
	if len(offers) != 1 {
		t.Fatalf("offers = %d, want 1", len(offers))
	}
	// Both terms project (unrestricted); headline pricing is the first one.
	if got := len(offers[0].GetTerms()); got != 2 {
		t.Fatalf("terms = %d, want 2 (both project)", got)
	}
	if got := offers[0].GetPricing().GetRate(); got != firstRate {
		t.Errorf("headline rate = %v, want %v (first projected term)", got, firstRate)
	}
}

// TestDiscover_RestrictedTermStillPricesAsRealOffer proves the priced-offer
// guarantee for a term carrying a USER_TYPE restriction: the offer derives its
// headline price from the real LicenseTerm's Pricing (here 0.05 PER_UNIT), never
// a $0.05 free/stub. Post-ADR-014 the restriction no longer gates discovery —
// the Exchange projects by scope/resource_id only and the restriction rides on
// the returned offer for the agent to self-honour — so a requester declaring the
// permitted user_type still gets exactly one priced offer for the real term.
// (The complementary "an ineligible requester gets no offer" leg is gone: the
// no-stub guarantee for a scope-ineligible requester is owned by the scope
// suite, and requester-attribute exclusion no longer exists.)
func TestDiscover_RestrictedTermStillPricesAsRealOffer(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const path = "/pricing/restricted"
	uri := "https://" + h.publisherDom + path
	pushTerms(t, h, client, callerID, path, userTypeTerm("academic-permitted", "academic"))

	// Any requester now discovers the term; the offer prices off the real term,
	// not a stub. Assert one offer carrying the real PER_UNIT 0.05 headline.
	academic := requesterWithExt("agent-academic", "academic", "")
	got := discoverOffersAs(t, h, uri, academic)
	if len(got) != 1 {
		t.Fatalf("offers = %d, want 1 (restricted term still projects as one real offer)", len(got))
	}
	if rate := got[0].GetPricing().GetRate(); rate != money(t, 0.05) {
		t.Fatalf("headline rate = %v, want %q (real term price, not a stub)", rate, money(t, 0.05))
	}
}

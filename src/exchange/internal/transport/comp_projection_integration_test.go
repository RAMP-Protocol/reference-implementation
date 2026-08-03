//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/comptest"
)

// mustWireRateFloat parses a canonical wire money string (the spine's
// exact-decimal Rate) into the lossy float64 the CoMP unitprice projection uses
// (scopeFromPricing -> InexactFloat64). The empty string (FREE / unset) maps to
// 0, matching the unitprice-0-conveys-free contract. Used by comp assertions
// that must compare the rendered float64 unitprice against the term's string
// rate.
func mustWireRateFloat(t *testing.T, rate string) float64 {
	t.Helper()
	if rate == "" {
		return 0
	}
	d, err := helpers.ParseMoney(rate)
	if err != nil {
		t.Fatalf("parse wire rate %q: %v", rate, err)
	}
	return d.InexactFloat64()
}

// TestComp_ProfileGatedPricingProjection is the profile-gated pricing-projection RED
// baseline: it pins profile-gated CoMP pricing projection on the Offer, observed
// END-TO-END through DiscoverResources only (no DB/internal access — Testing
// Doctrine pt 9). A publisher pushes ONE priced (PER_UNIT) ResourceEntry via
// CatalogService.PushResources; the test then drives three legs through the
// public RPC surface:
//
//	POSITIVE: discover WITH ResourceQuery.SupportedProfiles=["ramp-comp-v1"] →
//	  the returned Offer carries offer.Ext["comp"], a bare canonical CoMP V1
//	  Package whose scope mirrors the selected term's Pricing (unitprice==rate,
//	  cur==currency) and whose id is "<resourceID>#0"; the emitted comp Struct
//	  passes comptest.Validate (a real CoMP parser would accept it).
//
//	NEGATIVE (Doctrine pt 10): discover the SAME resource WITHOUT
//	  SupportedProfiles → NO "comp" key in offer.Ext, and base metadata behavior
//	  is intact (the offer still builds and carries term-derived pricing).
//
//	PARITY: ExecuteTransaction on the comp-bearing offer succeeds — proving the
//	  signed comp ext is reproduced byte-identically at tx-reconstruction
//	  (canonicalOfferPayload covers Offer.Ext).
//
// It FAILS on current HEAD: the Exchange never reads supported_profiles on the
// discovery path and emits no comp ext, so the POSITIVE leg's offer.Ext["comp"]
// lookup is absent (assertion failure, not a compile error — every RPC/field it
// uses already exists).
func TestComp_ProfileGatedPricingProjection(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	const compPath = "/articles/comp-priced"
	resourceID := "res-" + uuid.NewString()
	entry := &rampv1.ResourceEntry{
		ContentId: proto.String(resourceID),
		Domain:    h.publisherDom,
		Path:      compPath,
		Terms:     []*rampv1.LicenseTerm{seedPricedTerm()},
	}

	client := h.signedCat(callerID, priv)
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries:  []*rampv1.ResourceEntry{entry},
	}))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("accepted=%d rejected=%d, want 1/0", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}

	uri := "https://" + h.publisherDom + compPath
	term := seedPricedTerm()

	// POSITIVE: profile-aware discover renders the comp ext.
	compOffer := discoverCompOffer(t, h, uri)
	assertCompPricingProjection(t, compOffer, term)

	// NEGATIVE: profile-free discover renders NO comp ext, base path intact.
	baseOffer := singleOffer(t, h, uri)
	assertNoCompProjection(t, baseOffer, term)

	// PARITY: the signed comp ext survives tx-reconstruction.
	assertTransactParity(t, h, compOffer)
}

// discoverCompOffer discovers uri WITH SupportedProfiles=["ramp-comp-v1"] (the
// profile-aware read mirroring discoverOffersAs) and asserts exactly one offer.
// The plain discoverOffers helper sets no profiles; this one declares the CoMP
// profile so the Exchange is asked to project it.
//
// SHARED helper: used by the slice-1, slice-3, and slice-4 scenarios across the
// comp_*_integration_test.go files; it stays in this base file so those siblings
// reuse one definition (Go would reject a redeclaration).
func discoverCompOffer(t *testing.T, h *pushHarness, uri string) *rampv1.Offer {
	t.Helper()
	resp, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:               "1.0",
		Uris:              []string{uri},
		SupportedProfiles: []string{"ramp-comp-v1"},
		Requester: &rampv1.Requester{
			Id:     "agent-discover",
			Domain: "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("discover (comp profile) %s: %v", uri, err)
	}
	offers := resp.Msg.GetOffers()
	if len(offers) != 1 {
		t.Fatalf("discover (comp profile) %s: got %d offers, want 1", uri, len(offers))
	}
	return offers[0]
}

// assertCompPricingProjection verifies the comp ext the profile-aware discover
// emitted: a bare canonical CoMP V1 Package whose scope mirrors the selected
// term's Pricing, whose id is "<resourceID>#0", and which a real CoMP parser
// (comptest.Validate) accepts.
func assertCompPricingProjection(t *testing.T, o *rampv1.Offer, term *rampv1.LicenseTerm) {
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

	// Package.id == "<resource_id>#0" (Q8: <resource_id>#<term-index>). The
	// resource id is the Offer's own id (tenant-scoped composite the agent
	// transacts with), so derive the expectation from offer.OfferId — NOT the
	// bare pushed content_id, which the catalog tenant-prefixes.
	wantID := o.GetOfferId() + "#0"
	if got := fields["id"].GetStringValue(); got != wantID {
		t.Errorf("comp.id = %q, want %q", got, wantID)
	}

	// scope.unitprice == term Pricing.rate; scope.cur == term currency.
	scope := fields["scope"].GetStructValue()
	if scope == nil {
		t.Fatalf("comp.scope missing or not a Struct: %v", fields["scope"])
	}
	sf := scope.GetFields()
	// Rate is a canonical decimal STRING on the wire; CoMP unitprice is the lossy
	// float64 projection of it (scopeFromPricing). Parse the term's wire rate to
	// float64 the same way production does, then compare — same assertion strength
	// (unitprice equals the selected term's rate), adapted to the string spine.
	wantRate := mustWireRateFloat(t, term.GetPricing().GetRate())
	if got := sf["unitprice"].GetNumberValue(); got != wantRate {
		t.Errorf("comp.scope.unitprice = %v, want %v", got, wantRate)
	}
	wantCur := term.GetPricing().GetCurrency()
	if wantCur == "" {
		wantCur = "USD"
	}
	if got := sf["cur"].GetStringValue(); got != wantCur {
		t.Errorf("comp.scope.cur = %q, want %q", got, wantCur)
	}

	// The emitted comp Struct must validate as canonical CoMP V1 — a real CoMP
	// parser would accept it (UseEnumNumbers makes integer enums conformant).
	if err := comptest.Validate(comp); err != nil {
		t.Errorf("comptest.Validate(offer.ext[comp]) = %v, want nil", err)
	}
}

// assertNoCompProjection verifies the profile-free discover emitted NO comp ext
// (send-all base preserved, ADR-014) while base metadata behavior stays intact:
// the offer still builds and carries term-derived pricing.
func assertNoCompProjection(t *testing.T, o *rampv1.Offer, term *rampv1.LicenseTerm) {
	t.Helper()
	if _, ok := o.GetExt().GetFields()["comp"]; ok {
		t.Errorf("profile-free offer carries comp ext (gate leaked): ext=%v", o.GetExt())
	}
	// Base metadata path intact: pricing present and derived from the term.
	if o.GetPricing() == nil {
		t.Fatalf("profile-free offer has no pricing (base path regressed)")
	}
	if got := o.GetPricing().GetRate(); got != term.GetPricing().GetRate() {
		t.Errorf("profile-free offer pricing.rate = %v, want term-derived %v", got, term.GetPricing().GetRate())
	}
}

// numberList extracts a []float64 from a structpb list value (protojson encodes
// repeated int32 as a JSON number array).
//
// SHARED helper: used by the slice-2 and slice-3 scenarios; kept in this base
// file so those sibling files reuse one definition.
func numberList(v *structpb.Value) []float64 {
	lv := v.GetListValue()
	out := make([]float64, 0, len(lv.GetValues()))
	for _, e := range lv.GetValues() {
		out = append(out, e.GetNumberValue())
	}
	return out
}

// floatSliceEqual reports element-wise equality of two float slices.
//
// SHARED helper: used by the slice-2 and slice-3 scenarios; kept in this base
// file so those sibling files reuse one definition.
func floatSliceEqual(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

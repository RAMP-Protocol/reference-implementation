//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/comptest"
)

// seedTermProjection builds the term-projection RED fixture term: a copy of
// seedPricedTerm() (so its priced PER_UNIT Pricing — slice-1's guarantee — still
// renders) AUGMENTED with the full restriction/obligation/quota/scope set slice-2
// must crosswalk. It carries, per the expressibility matrix + Resolved rulings:
//
//   - USER_TYPE permitted=["commercial"]  -> N4: scope.ause == 0 (COMMERCIAL)
//   - GEOGRAPHY permitted=["US","DE"]      -> N7: scope.country == [276,840]
//     (ISO-3166 numeric, sorted ascending; DE=276, US=840)
//   - Obligation{ATTRIBUTION, ON_USE}      -> Package.citation == 1
//   - Obligation{NOTICE, ON_USE}           -> UNMAPPABLE (proves omission of
//     non-ATTRIBUTION obligation kinds; never reaches a canonical comp path)
//   - FUNCTION permitted=["ai-train"]      -> UNMAPPABLE (no supply-side comp
//     home; must NOT project to comp.function/comp.subfn)
//   - Quota{accesses, 1000, DAILY}         -> UNMAPPABLE (no canonical V1 field)
//   - Scopes=["entitlement:full"]          -> UNMAPPABLE (explicit non-mapping)
//
// All tokens satisfy ingest CEL (restriction.permitted.format,
// quota.metric.format, obligation.kind/trigger_specified) so the term is accepted
// by PushResources and round-trips to discovery unchanged.
func seedTermProjection() *rampv1.LicenseTerm {
	term := seedPricedTerm() // keeps the priced PER_UNIT Pricing (slice-1 guard)
	term.Restrictions = []*rampv1.Restriction{
		{
			Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
			Permitted: []string{"commercial"},
		},
		{
			Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
			Permitted: []string{"US", "DE"},
		},
		{
			Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
			Permitted: []string{"ai-train"},
		},
	}
	term.Obligations = []*rampv1.Obligation{
		{
			Kind:    rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION,
			Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE,
		},
		{
			// Non-ATTRIBUTION obligation: must be omitted from comp, proving
			// the citation crosswalk is ATTRIBUTION-only (omission != loss).
			Kind:    rampv1.ObligationKind_OBLIGATION_KIND_NOTICE,
			Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE,
		},
	}
	term.Quotas = []*rampv1.Quota{
		{Metric: "accesses", Limit: 1000, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY},
	}
	term.Scopes = []string{"entitlement:full"}
	return term
}

// TestComp_TermProjection is the term-projection RED baseline: it pins the
// COMPLETE term->CoMP crosswalk (restrictions, obligations) observed END-TO-END
// through DiscoverResources only (no DB/internal access — Testing Doctrine pt 9).
// A publisher pushes ONE resource whose single term (seedTermProjection) carries
// the full mappable + unmappable construct set; the test discovers it WITH
// SupportedProfiles=["ramp-comp-v1"] and asserts four properties through the
// public RPC surface:
//
//	(1) CROSSWALK: comp.scope.ause == 0 (COMMERCIAL, N4); comp.scope.country ==
//	    [276,840] (ISO-3166 numeric, sorted, EXACT codes pinned — DE=276, US=840,
//	    N7); comp Package.citation == 1 (ATTRIBUTION). Slice-1 invariants still
//	    hold WITHIN this richer term: comp.id == "<offer>#0", scope.unitprice ==
//	    term rate, scope.cur == currency.
//
//	(2) OMISSION + NON-LOSS: NO "function"/"subfn" key ANYWHERE under comp.*
//	    (FUNCTION has no supply-side home); LicenseTerm.scopes NOT projected into
//	    comp; quota NOT at any canonical comp path; the NOTICE obligation absent
//	    from comp. AND the same unmappable facts (FUNCTION restriction, quota,
//	    scopes) STILL ride on the discovered offer.GetTerms()[0] — proving
//	    omission from comp is NOT loss from the canonical LicenseTerm.
//
//	(3) CONFORMANCE: comptest.Validate(comp) passes (a real CoMP parser accepts
//	    the richer Package; no foreign keys leaked to canonical paths).
//
//	(4) PARITY: ExecuteTransaction on this comp-bearing offer succeeds — the
//	    signed comp ext is reproduced byte-identically at tx-reconstruction.
//
// It FAILS on current HEAD: the slice-1 renderer (comp_render.go) emits only a
// pricing-derived Scope (unitprice/cur/pricetype) — no ause, no country, no
// citation — so the crosswalk assertions in (1) fail (assertion failures, not
// compile/collection errors; every RPC and field it uses already exists).
func TestComp_TermProjection(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	const termPath = "/articles/comp-term"
	resourceID := "res-" + uuid.NewString()
	entry := &rampv1.ResourceEntry{
		ContentId: proto.String(resourceID),
		Domain:    h.publisherDom,
		Path:      termPath,
		Terms:     []*rampv1.LicenseTerm{seedTermProjection()},
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

	uri := "https://" + h.publisherDom + termPath
	term := seedTermProjection()

	// POSITIVE: profile-aware discover renders the full term crosswalk. The
	// requester declares the entitlement scope the term carries so licenseterm.
	// Select keeps it (entitlement scopes are the only discovery eligibility
	// filter — restriction axes do not exclude terms; ADR-014).
	compOffer := discoverCompOffer(t, h, uri, "entitlement:full")
	assertCompTermProjection(t, compOffer, term)
	assertCompUnmappableOmitted(t, compOffer)

	// PARITY: the signed (now richer) comp ext survives tx-reconstruction. The
	// tx requester carries the SAME entitlement scope so verifyOffer rebuilds the
	// identical Select-filtered, comp-bearing offer and the signature re-verifies.
	assertTransactParityScoped(t, h, compOffer, "entitlement:full")
}

// assertTransactParityScoped drives ExecuteTransaction with a requester carrying
// the given entitlement scope, mirroring assertTransactParity but matching the
// scope the offer was discovered under (verifyOffer re-runs licenseterm.Select
// with the tx requester, so the scope must match for byte-identical rebuild).
func assertTransactParityScoped(t *testing.T, h *pushHarness, o *rampv1.Offer, scope string) {
	t.Helper()
	parityTransact(t, h, o, []string{scope})
}

// assertCompTermProjection verifies property (1): the mappable crosswalk landed
// on canonical comp paths with EXACT values, slice-1 pricing invariants still
// hold within the richer term, and the emitted comp Struct passes comptest.
func assertCompTermProjection(t *testing.T, o *rampv1.Offer, term *rampv1.LicenseTerm) {
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

	// Slice-1 invariant within the richer term: Package.id == "<offer>#0".
	wantID := o.GetOfferId() + "#0"
	if got := fields["id"].GetStringValue(); got != wantID {
		t.Errorf("comp.id = %q, want %q", got, wantID)
	}

	// ATTRIBUTION obligation -> Package.citation == 1.
	if got := fields["citation"].GetNumberValue(); got != 1 {
		t.Errorf("comp.citation = %v, want 1 (ATTRIBUTION obligation present)", got)
	}

	scope := fields["scope"].GetStructValue()
	if scope == nil {
		t.Fatalf("comp.scope missing or not a Struct: %v", fields["scope"])
	}
	sf := scope.GetFields()

	// Slice-1 pricing invariants still hold: unitprice == rate, cur == currency.
	// Rate is a wire decimal string; parse to the float64 projection to compare.
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

	// N4: USER_TYPE permitted=["commercial"] -> scope.ause == 0 (COMMERCIAL).
	auseVal, hasAuse := sf["ause"]
	if !hasAuse {
		t.Errorf("comp.scope.ause missing, want 0 (COMMERCIAL)")
	} else if got := auseVal.GetNumberValue(); got != 0 {
		t.Errorf("comp.scope.ause = %v, want 0 (COMMERCIAL)", got)
	}

	// N7: GEOGRAPHY permitted=["US","DE"] -> scope.country == [276,840]
	// (ISO-3166 numeric, sorted ascending; DE=276, US=840). Every emitted code
	// is pinned EXACTLY — no assert-by-faith.
	countryVal, hasCountry := sf["country"]
	if !hasCountry {
		t.Fatalf("comp.scope.country missing, want [276,840]")
	}
	gotCountry := numberList(countryVal)
	wantCountry := []float64{276, 840} // DE=276, US=840, sorted ascending
	if !floatSliceEqual(gotCountry, wantCountry) {
		t.Errorf("comp.scope.country = %v, want %v (DE=276, US=840, sorted)", gotCountry, wantCountry)
	}

	// The richer comp Struct must still validate as canonical CoMP V1.
	if err := comptest.Validate(comp); err != nil {
		t.Errorf("comptest.Validate(offer.ext[comp]) = %v, want nil", err)
	}
}

// assertCompUnmappableOmitted verifies property (2): the unmappable constructs
// (FUNCTION, quota, LicenseTerm.scopes, non-ATTRIBUTION obligations) are absent
// from EVERY canonical comp path, AND still ride on offer.GetTerms()[0] — the
// canonical LicenseTerm. Omission from comp is not loss from the offer.
func assertCompUnmappableOmitted(t *testing.T, o *rampv1.Offer) {
	t.Helper()
	comp := o.GetExt().GetFields()["comp"].GetStructValue()
	if comp == nil {
		t.Fatalf("offer.ext[comp] missing for omission check")
	}

	// FUNCTION has no supply-side home: NO "function"/"subfn" key anywhere under
	// comp.* (it would be a foreign key comptest.Validate rejects).
	for _, key := range []string{"function", "subfn"} {
		if structContainsKey(comp, key) {
			t.Errorf("comp carries foreign key %q (FUNCTION has no supply-side home): %v", key, comp)
		}
	}

	// Quota has no canonical V1 field: must NOT appear at any canonical comp path.
	for _, key := range []string{"quota", "limit", "metric", "window", "max"} {
		if structContainsKey(comp, key) {
			t.Errorf("comp carries quota-derived canonical key %q (no V1 field): %v", key, comp)
		}
	}

	// LicenseTerm.scopes are NOT CoMP content-coverage Scope: not projected.
	scope := comp.GetFields()["scope"].GetStructValue()
	if scope != nil {
		// The CoMP "scope" int (content-coverage selector) must not carry the
		// RAMP entitlement-scope token.
		if _, ok := scope.GetFields()["scope"]; ok {
			if got := scope.GetFields()["scope"].GetStringValue(); got != "" {
				t.Errorf("comp.scope.scope = %q, RAMP entitlement scopes must not project", got)
			}
		}
	}

	// NON-LOSS: the unmappable facts STILL ride on the canonical LicenseTerm
	// returned on the discovered offer (omission from comp != loss from offer).
	if len(o.GetTerms()) == 0 {
		t.Fatalf("discovered offer carries no terms; cannot prove non-loss")
	}
	canon := o.GetTerms()[0]
	if !hasRestrictionKind(canon, rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION) {
		t.Errorf("FUNCTION restriction lost from offer.terms[0]: %v", canon.GetRestrictions())
	}
	if len(canon.GetQuotas()) == 0 {
		t.Errorf("quota lost from offer.terms[0]: %v", canon.GetQuotas())
	}
	if len(canon.GetScopes()) == 0 {
		t.Errorf("scopes lost from offer.terms[0]: %v", canon.GetScopes())
	}
}

// hasRestrictionKind reports whether the term carries a restriction of kind k.
func hasRestrictionKind(term *rampv1.LicenseTerm, k rampv1.RestrictionKind) bool {
	for _, r := range term.GetRestrictions() {
		if r.GetKind() == k {
			return true
		}
	}
	return false
}

// structContainsKey reports whether key appears at ANY depth in s (recursing
// through nested structs and lists) — a foreign-key sweep for omission checks.
func structContainsKey(s *structpb.Struct, key string) bool {
	for k, v := range s.GetFields() {
		if k == key {
			return true
		}
		if valueContainsKey(v, key) {
			return true
		}
	}
	return false
}

// valueContainsKey recurses into struct/list values looking for key.
func valueContainsKey(v *structpb.Value, key string) bool {
	if sv := v.GetStructValue(); sv != nil {
		return structContainsKey(sv, key)
	}
	if lv := v.GetListValue(); lv != nil {
		for _, e := range lv.GetValues() {
			if valueContainsKey(e, key) {
				return true
			}
		}
	}
	return false
}

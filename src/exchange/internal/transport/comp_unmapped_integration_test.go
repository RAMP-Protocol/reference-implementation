//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/comptest"
)

// seedUnmappedTerm builds the unmapped-constructs RED fixture term: a copy of
// seedPricedTerm() (so its priced PER_UNIT Pricing renders to comp.scope) AUGMENTED
// with a mix of MAPPED constructs (which must NOT be flagged) and UNMAPPED
// constructs (which the renderer must surface under comp.ext.ramp_unmapped). Per
// the resolved design and triage resolution:
//
// MAPPED (must NOT appear in ramp_unmapped):
//   - GEOGRAPHY permitted=["US"]          -> crosswalks to comp.scope.country
//
// (A mapped USER_TYPE is not added separately: protovalidate allows at most one
// restriction per kind, and the single USER_TYPE restriction is reserved for the
// result-based unmapped case below. GEOGRAPHY ["US"] carries the mapped-not-flagged
// proof on its own — the atom permits "MAPPED USER_TYPE and/or GEOGRAPHY".)
//
// UNMAPPED (must appear in ramp_unmapped, sorted+deduped):
//   - FUNCTION permitted=["ai-train"]     -> "restriction:function" (no comp home)
//   - USER_TYPE permitted=["martians"]    -> "restriction:user_type" — the
//     RESULT-BASED case: "martians" is an UNRECOGNIZED token (NOT in the ause
//     crosswalk), so this restriction contributes NO comp.scope.ause token and is
//     therefore unmapped. A KIND-level classifier would WRONGLY treat any USER_TYPE
//     restriction as mapped; this fixture forces result-based classification.
//   - Quota{accesses, 1000, DAILY}        -> "quota:accesses" (no canonical V1 field)
//   - Obligation{NOTICE, ON_USE}          -> "obligation:notice" — a non-ATTRIBUTION
//     obligation kind (the citation crosswalk is ATTRIBUTION-only). NOTICE is used
//     in place of SHARE_ALIKE because SHARE_ALIKE without scope_license is a hard
//     ingest reject (licenseterm.Validate); NOTICE ingests cleanly and is still a
//     non-ATTRIBUTION kind, satisfying the slice's "obligation:<kind>" requirement.
//   - Scopes=["entitlement:full"]         -> "scope:entitlement:full"
//
// All tokens satisfy ingest CEL: "martians" / "ai-train" are open-vocab restriction
// tokens (unregistered -> non-fatal warning, term accepted), "accesses" is a
// registered Quota.metric, and NOTICE carries no mandatory detail. So PushResources
// accepts the term and it round-trips to discovery unchanged.
func seedUnmappedTerm() *rampv1.LicenseTerm {
	term := seedPricedTerm() // keeps the priced PER_UNIT Pricing so comp.scope renders.
	// protovalidate allows at most ONE restriction per kind, so the mapped-construct
	// proof rides on GEOGRAPHY (["US"] -> comp.scope.country, absent from
	// ramp_unmapped) and the single USER_TYPE restriction is the RESULT-BASED
	// unmapped case (only an unrecognized token -> no ause -> flagged).
	term.Restrictions = []*rampv1.Restriction{
		{
			// MAPPED: recognized GEOGRAPHY token -> comp.scope.country.
			Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
			Permitted: []string{"US"},
		},
		{
			// UNMAPPED (kind): FUNCTION has no comp home -> "restriction:function".
			Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
			Permitted: []string{"ai-train"},
		},
		{
			// UNMAPPED (RESULT-BASED): USER_TYPE with only an UNRECOGNIZED token
			// ("martians", NOT in the ause crosswalk) contributes no comp.scope.ause
			// -> "restriction:user_type". A KIND-level classifier would WRONGLY treat
			// this USER_TYPE restriction as mapped; this fixture catches that.
			Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
			Permitted: []string{"martians"},
		},
	}
	term.Obligations = []*rampv1.Obligation{
		{
			// UNMAPPED: non-ATTRIBUTION obligation -> "obligation:notice".
			Kind:    rampv1.ObligationKind_OBLIGATION_KIND_NOTICE,
			Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE,
		},
	}
	term.Quotas = []*rampv1.Quota{
		// UNMAPPED: any quota -> "quota:accesses".
		{Metric: "accesses", Limit: 1000, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY},
	}
	// UNMAPPED: every term scope -> "scope:entitlement:full".
	term.Scopes = []string{"entitlement:full"}
	return term
}

// wantUnmapped is the EXACT sorted, deduped ramp_unmapped set the .12 renderer must
// emit for seedUnmappedTerm. Pinned verbatim — the mapped commercial/US constructs
// are deliberately ABSENT, and the result-based restriction:user_type is present.
var wantUnmapped = []string{
	"obligation:notice",
	"quota:accesses",
	"restriction:function",
	"restriction:user_type",
	"scope:entitlement:full",
}

// TestComp_UnmappedConstructsFlag is the unmapped-constructs RED baseline. It
// pins lossy-projection TRANSPARENCY observed END-TO-END through DiscoverResources
// only (no DB/internal access — Testing Doctrine pt 9): when a term carries RAMP
// constructs with no CoMP projection, the renderer must SIGNAL them under the
// oracle-opaque comp Package.ext as ramp_unmapped (a sorted, deduped []string) —
// never misrepresent, never drop silently — while the full canonical LicenseTerm
// keeps riding on Offer.terms[].
//
// A publisher pushes ONE resource whose single
// term (seedUnmappedTerm) carries the mapped (GEOGRAPHY=US) + unmapped (FUNCTION, an
// UNRECOGNIZED-token USER_TYPE, a quota, a NOTICE obligation, an entitlement scope)
// construct set. The test discovers it WITH SupportedProfiles=["ramp-comp-v1"] and
// the term's entitlement scope (so licenseterm.Select keeps the scope-bearing term)
// and asserts four properties through the public RPC surface:
//
//	(1) FLAG: comp.ext.ramp_unmapped == wantUnmapped EXACTLY (sorted, deduped,
//	    every entry pinned). The mapped US construct does NOT appear, and the
//	    result-based restriction:user_type (unrecognized "martians" token) DOES.
//
//	(2) NON-LOSS: the unmappable facts STILL ride on the discovered
//	    offer.GetTerms()[0] — the FUNCTION restriction, the unrecognized USER_TYPE
//	    restriction, the quota, the NOTICE obligation, and the scope are all intact.
//	    Flagging in comp is not loss from the canonical LicenseTerm.
//
//	(3) CONFORMANCE: comptest.Validate(comp) passes — ramp_unmapped lives under the
//	    opaque comp Package.ext, so a real CoMP parser still accepts the Package.
//
//	(4) PARITY: ExecuteTransaction on this comp-bearing offer succeeds — the
//	    deterministic (sorted) ramp_unmapped list reproduces byte-identically at
//	    tx-reconstruction, so the signature re-verifies.
//
// It FAILS on current HEAD: renderCompProfile (comp_render.go) emits no
// comp.ext.ramp_unmapped key at all (citationFromObligations is ATTRIBUTION-only,
// FUNCTION/quota/scopes are silently omitted, and no ext.ramp_unmapped is built),
// so property (1) fails as an assertion failure — every RPC and field it uses
// already exists, so this is a behavioral red, not a compile/collection error.
func TestComp_UnmappedConstructsFlag(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	const termPath = "/articles/comp-unmapped"
	resourceID := "res-" + uuid.NewString()
	entry := &rampv1.ResourceEntry{
		ContentId: proto.String(resourceID),
		Domain:    h.publisherDom,
		Path:      termPath,
		Terms:     []*rampv1.LicenseTerm{seedUnmappedTerm()},
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

	// POSITIVE: profile-aware discover with the term's entitlement scope so Select
	// keeps the scope-bearing term (entitlement scopes are the only discovery
	// eligibility filter — restriction axes do not exclude terms; ADR-014).
	compOffer := discoverCompOffer(t, h, uri, "entitlement:full")
	assertCompRampUnmapped(t, compOffer)
	assertUnmappedNonLoss(t, compOffer)

	// PARITY: the signed (now ramp_unmapped-bearing) comp ext survives
	// tx-reconstruction under the same entitlement scope.
	assertTransactParityScoped(t, h, compOffer, "entitlement:full")
}

// assertCompRampUnmapped verifies properties (1) and (3): comp.ext.ramp_unmapped
// equals wantUnmapped exactly (sorted, deduped, mapped constructs absent), and the
// comp Package still validates as canonical CoMP V1 (ramp_unmapped is under the
// opaque Package.ext).
func assertCompRampUnmapped(t *testing.T, o *rampv1.Offer) {
	t.Helper()
	compVal, ok := o.GetExt().GetFields()["comp"]
	if !ok || compVal == nil {
		t.Fatalf("offer.ext has no %q key under ramp-comp-v1: ext=%v", "comp", o.GetExt())
	}
	comp := compVal.GetStructValue()
	if comp == nil {
		t.Fatalf("offer.ext[comp] is not a Struct: %v", compVal)
	}

	// ramp_unmapped lives under the comp Package's opaque "ext" object.
	ext := comp.GetFields()["ext"].GetStructValue()
	if ext == nil {
		t.Fatalf("comp.ext missing or not a Struct: %v", comp.GetFields()["ext"])
	}
	unmappedVal, has := ext.GetFields()["ramp_unmapped"]
	if !has {
		t.Fatalf("comp.ext.ramp_unmapped missing; want %v", wantUnmapped)
	}
	got := stringList(unmappedVal)
	if !slices.Equal(got, wantUnmapped) {
		t.Errorf("comp.ext.ramp_unmapped = %v, want %v (sorted, deduped; mapped commercial/US absent, result-based restriction:user_type present)", got, wantUnmapped)
	}

	// CONFORMANCE: ramp_unmapped under opaque Package.ext must not trip the oracle.
	if err := comptest.Validate(comp); err != nil {
		t.Errorf("comptest.Validate(offer.ext[comp]) = %v, want nil (ramp_unmapped is under opaque comp.ext)", err)
	}
}

// assertUnmappedNonLoss verifies property (2): every flagged-as-unmapped construct
// STILL rides on the discovered offer.GetTerms()[0] — the canonical LicenseTerm.
// Flagging in comp is not loss from the offer.
func assertUnmappedNonLoss(t *testing.T, o *rampv1.Offer) {
	t.Helper()
	if len(o.GetTerms()) == 0 {
		t.Fatalf("discovered offer carries no terms; cannot prove non-loss")
	}
	canon := o.GetTerms()[0]

	if !hasRestrictionKind(canon, rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION) {
		t.Errorf("FUNCTION restriction lost from offer.terms[0]: %v", canon.GetRestrictions())
	}
	if !hasUnrecognizedUserType(canon, "martians") {
		t.Errorf("unrecognized USER_TYPE restriction (martians) lost from offer.terms[0]: %v", canon.GetRestrictions())
	}
	if len(canon.GetQuotas()) == 0 {
		t.Errorf("quota lost from offer.terms[0]: %v", canon.GetQuotas())
	}
	if !hasObligationKind(canon, rampv1.ObligationKind_OBLIGATION_KIND_NOTICE) {
		t.Errorf("NOTICE obligation lost from offer.terms[0]: %v", canon.GetObligations())
	}
	if len(canon.GetScopes()) == 0 {
		t.Errorf("scopes lost from offer.terms[0]: %v", canon.GetScopes())
	}
}

// hasUnrecognizedUserType reports whether the term carries a USER_TYPE restriction
// whose Permitted[] includes the given (unrecognized) token.
func hasUnrecognizedUserType(term *rampv1.LicenseTerm, token string) bool {
	for _, r := range term.GetRestrictions() {
		if r.GetKind() != rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE {
			continue
		}
		if slices.Contains(r.GetPermitted(), token) {
			return true
		}
	}
	return false
}

// hasObligationKind reports whether the term carries an obligation of kind k.
func hasObligationKind(term *rampv1.LicenseTerm, k rampv1.ObligationKind) bool {
	for _, o := range term.GetObligations() {
		if o.GetKind() == k {
			return true
		}
	}
	return false
}

// stringList extracts a []string from a structpb list value (protojson encodes a
// repeated string field — here comp.ext.ramp_unmapped — as a JSON string array).
func stringList(v *structpb.Value) []string {
	lv := v.GetListValue()
	out := make([]string, 0, len(lv.GetValues()))
	for _, e := range lv.GetValues() {
		out = append(out, e.GetStringValue())
	}
	return out
}

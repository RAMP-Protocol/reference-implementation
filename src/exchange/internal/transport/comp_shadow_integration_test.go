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

// publisherShadowExt builds the publisher's raw resource ext (the metadata
// pass-through) carrying a "comp" object that exercises BOTH halves of the
// term-authoritative shadow rule:
//
//	(a) comp.ext.publisher_note = "keep-me" — a NON-owned opaque key the renderer
//	    never sets, parked under the oracle-opaque "ext" sub-object so
//	    comptest.Validate stays clean. The merge MUST preserve it.
//
//	(b) comp.scope.unitprice = 0.0 — a term-OWNED field the publisher contradicts
//	    (claims free) while the selected term is seedPricedTerm (PER_UNIT $0.05).
//	    The merge MUST let the TERM win (0.05), not the publisher's 0.0.
//
// applyMetadata aliases this struct onto offer.Ext wholesale (metadata_codec.go),
// so offer.Ext["comp"] is the publisher base the renderer then deep-merges its
// term-rendered comp OVER.
func publisherShadowExt(t *testing.T) *structpb.Struct {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{
		"comp": map[string]any{
			"ext": map[string]any{
				"publisher_note": "keep-me",
			},
			"scope": map[string]any{
				"unitprice": 0.0, // publisher claims free; the term must override
			},
		},
	})
	if err != nil {
		t.Fatalf("build publisher shadow ext: %v", err)
	}
	return ext
}

// TestComp_TermShadowsPublisherExt is the term-shadows-publisher-ext RED baseline: it pins
// the TERM-AUTHORITATIVE SHADOW rule — the rendered comp ext is a DEEP MERGE of
// the term-rendered fields OVER the publisher's raw ext.comp, where publisher
// non-owned keys SURVIVE but term-owned keys WIN on conflict — observed
// END-TO-END through DiscoverResources only (no DB/internal access — Testing
// Doctrine pt 9).
//
// A publisher pushes ONE priced (PER_UNIT $0.05) ResourceEntry whose raw ext
// carries a "comp" object with BOTH (a) a non-owned opaque key
// (comp.ext.publisher_note="keep-me") and (b) a CONTRADICTING term-owned value
// (comp.scope.unitprice=0.0, "free"). The test discovers it WITH
// SupportedProfiles=["ramp-comp-v1"] and asserts, through the public Offer:
//
//	HALF (a) PRESERVATION: offer.Ext["comp"].ext.publisher_note == "keep-me" —
//	  the publisher's non-owned key survives the merge (not clobbered).
//
//	HALF (b) OVERRIDE: offer.Ext["comp"].scope.unitprice == 0.05 (the TERM rate),
//	  NOT the publisher's 0.0 — the term-owned field wins on conflict.
//
//	CONFORMANCE: comptest.Validate(comp) passes — the surviving publisher key sits
//	  under the oracle-opaque comp.ext sub-object, so no foreign key is resurrected
//	  at a canonical CoMP path.
//
//	PARITY: ExecuteTransaction on the merged-comp-bearing offer succeeds — the
//	  signed merged ext is reproduced byte-identically at tx-reconstruction
//	  (the deterministic merge renders identical bytes on both paths).
//
// It FAILS on current HEAD: applyCompProfile (comp_render.go) replaces the whole
// "comp" key WHOLESALE via withField, so the publisher's comp.ext.publisher_note
// is DROPPED — HALF (a) fails (an assertion failure, not a compile/collection
// error; every RPC and field it uses already exists). HALF (b) already holds by
// the clobber, so the two-half assertion isolates the missing PRESERVATION
// behavior this slice adds.
func TestComp_TermShadowsPublisherExt(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	const shadowPath = "/articles/comp-shadow"
	entry := &rampv1.ResourceEntry{
		ContentId: proto.String("res-" + uuid.NewString()),
		Domain:    h.publisherDom,
		Path:      shadowPath,
		Ext:       publisherShadowExt(t), // publisher comp.ext + contradicting comp.scope
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

	uri := "https://" + h.publisherDom + shadowPath

	// POSITIVE: profile-aware discover renders comp by deep-merging the
	// term-rendered fields OVER the publisher's raw ext.comp.
	compOffer := discoverCompOffer(t, h, uri)
	assertCompTermShadow(t, compOffer)

	// PARITY: the signed merged comp ext survives tx-reconstruction byte-identically.
	assertTransactParity(t, h, compOffer)
}

// assertCompTermShadow verifies both halves of the shadow rule on the discovered
// offer plus conformance: (a) the publisher's non-owned comp.ext.publisher_note
// survives the merge; (b) the term-owned comp.scope.unitprice is the TERM rate
// (0.05), NOT the publisher's contradicting 0.0; and comptest.Validate accepts the
// merged Package (the surviving publisher key lives under the opaque comp.ext).
func assertCompTermShadow(t *testing.T, o *rampv1.Offer) {
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

	// HALF (a) PRESERVATION: the publisher's non-owned key survives the merge.
	compExt := fields["ext"].GetStructValue()
	if compExt == nil {
		t.Fatalf("comp.ext missing or not a Struct (publisher non-owned key dropped — clobber): comp=%v", comp)
	}
	if got := compExt.GetFields()["publisher_note"].GetStringValue(); got != "keep-me" {
		t.Errorf("comp.ext.publisher_note = %q, want %q (publisher non-owned key must survive the merge)", got, "keep-me")
	}

	// HALF (b) OVERRIDE: the term-owned field wins over the publisher's value.
	scope := fields["scope"].GetStructValue()
	if scope == nil {
		t.Fatalf("comp.scope missing or not a Struct: %v", fields["scope"])
	}
	const wantTermRate = 0.05 // seedPricedTerm PER_UNIT rate; NOT the publisher's 0.0
	if got := scope.GetFields()["unitprice"].GetNumberValue(); got != wantTermRate {
		t.Errorf("comp.scope.unitprice = %v, want %v (term must override publisher's contradicting 0.0)", got, wantTermRate)
	}

	// CONFORMANCE: the merged Package is canonical CoMP V1 — the surviving
	// publisher key sits under the oracle-opaque comp.ext, no foreign canonical key.
	if err := comptest.Validate(comp); err != nil {
		t.Errorf("comptest.Validate(offer.ext[comp]) = %v, want nil", err)
	}
}

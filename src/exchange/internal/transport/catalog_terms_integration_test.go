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
)

// TestPushResources_TermsRoundTrip proves the vertical slice as a FULL
// protocol round-trip: a publisher pushes a ResourceEntry carrying multiple
// LicenseTerms via CatalogService.PushResources, and the exact terms read back
// — proto-equal, order preserved — through the public read surface
// DiscoverResources → Offer.terms. Both terms here are already canonical (no
// restriction tokens), so Normalize is a no-op and the shapes survive intact.
//
// This closes the earlier gap: the repo.ByID fallback the earlier version used is
// gone now that the discovery projection exposes terms publicly. No
// DB/repo/sqlc access (Testing Doctrine pt 9).
func TestPushResources_TermsRoundTrip(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	// Two distinct terms: an ENUMERATED term with explicit pricing and a
	// REFERENCE_ONLY term governed by a license document. Together they
	// exercise the oneof Pricing/License fields so the round-trip proves the
	// full LicenseTerm shape survives, not just a trivial scalar.
	rate := money(t, 0.07)
	wantTerms := []*rampv1.LicenseTerm{
		{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing: &rampv1.Pricing{
				Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
				Rate:     rate,
				Currency: "USD",
				Unit:     proto.String("accesses"),
			},
		},
		{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
			License: &rampv1.License{
				Uri:       proto.String("https://" + h.publisherDom + "/license.txt"),
				UriDigest: proto.String("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			},
			// Pricing is required on EVERY term regardless of semantics
			// a REFERENCE_ONLY term states its price here too,
			// its License only governs the human-readable terms.
			Pricing: &rampv1.Pricing{
				Model:    rampv1.PricingModel_PRICING_MODEL_FREE,
				Currency: "USD",
			},
		},
	}

	const path = "/articles/terms-roundtrip"
	contentID := "res-" + uuid.NewString()
	client := h.signedCat(callerID, priv)
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
		ContentId: proto.String(contentID),
		Domain:    h.publisherDom,
		Path:      path,
		Terms:     wantTerms,
	}})))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("accepted=%d rejected=%d, want 1/0", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}

	gotTerms := discoverTerms(t, h, "https://"+h.publisherDom+path)
	if len(gotTerms) != len(wantTerms) {
		t.Fatalf("terms len = %d, want %d", len(gotTerms), len(wantTerms))
	}
	for i := range wantTerms {
		if !proto.Equal(gotTerms[i], wantTerms[i]) {
			t.Fatalf("term %d round-trip mismatch:\n got = %v\nwant = %v", i, gotTerms[i], wantTerms[i])
		}
	}
}

// TestPushResources_NoTermsYieldsNoOffer covers the absent-terms edge under the
// term-derived pricing invariant: a push with no terms persists a
// well-formed empty JSON array (the termsOrEmpty default behind the NOT NULL
// terms column), but because there is no LicenseTerm to derive a price from, the
// entry yields NO offer — it is never silently priced at the retired $0.05
// default. The resource is still in the catalog (it was accepted); it just has
// no priced offer. Observed through the public surface.
func TestPushResources_NoTermsYieldsNoOffer(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	const path = "/articles/no-terms"
	contentID := "res-" + uuid.NewString()
	client := h.signedCat(callerID, priv)
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
		ContentId: proto.String(contentID),
		Domain:    h.publisherDom,
		Path:      path,
	}})))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 {
		t.Fatalf("accepted=%d, want 1", resp.Msg.GetAccepted())
	}
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+path); got != 0 {
		t.Fatalf("offers = %d, want 0 (no term → no price → no offer)", got)
	}
}

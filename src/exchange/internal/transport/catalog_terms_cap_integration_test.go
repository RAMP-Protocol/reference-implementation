//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// maxTermsPerEntry is the terms cap the wire carries:
// ResourceEntry.terms holds (buf.validate.field).repeated.max_items, and the
// number there is the only copy. The Exchange used to hold a second copy as a
// service constant and enforce it per entry, after the wire tier had already
// admitted the request. A second copy of a wire rule is a drift point, and the
// per-entry path it guarded became unreachable once the rule moved onto the
// field, so both were deleted; a test anchored on the constant would have kept
// passing against a cap the wire no longer carried.
func maxTermsPerEntry(t *testing.T) int {
	t.Helper()
	return wireBound(t, "ResourceEntry", "terms")
}

// pricedTerms builds n copies of the minimal valid ENUMERATED term. Every
// element is identical and individually valid, so the only axis a cap test
// exercises is the array LENGTH, not per-term validity.
func pricedTerms(n int) []*rampv1.LicenseTerm {
	out := make([]*rampv1.LicenseTerm, 0, n)
	for range n {
		out = append(out, &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String("accesses")},
		})
	}
	return out
}

// TestPushResources_TermsCardinalityCap proves the terms cap as the wire tier
// enforces it, through the public Connect surface. ResourceEntry.terms is
// bounded on the wire so every implementation refuses the same size; here the
// validate interceptor refuses the WHOLE submission at the RPC boundary, before
// any per-entry classification runs, and nothing is persisted. An entry at the
// cap is accepted and stored; one term over is refused.
//
// Both legs assert only through public surfaces: the PushResources verdict, and
// the DiscoverResources offer count as the persistence probe (one offer ⇒ the
// entry reached the catalog, zero ⇒ it did not) — a protocol round-trip on both
// legs, no DB/repo/sqlc access. The refusal additionally has to name WHICH tier
// refused: the buf.validate.Violations detail the interceptor attaches, with a
// violation on entries[0].terms under repeated.max_items. Without that check a
// refusal from any later gate would also read as InvalidArgument with zero
// offers, and the test would pass while the cap had silently moved.
func TestPushResources_TermsCardinalityCap(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)
	capacity := maxTermsPerEntry(t)

	cases := []struct {
		name       string
		path       string
		count      int
		wantErr    bool
		wantOffers int
	}{
		{
			name:       "exactly at the cap is accepted and persisted",
			path:       "/cap/at-limit",
			count:      capacity,
			wantOffers: 1,
		},
		{
			name:    "one over the cap is refused at the wire and not persisted",
			path:    "/cap/over-limit",
			count:   capacity + 1,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
				Domain: h.publisherDom,
				Path:   tc.path,
				Terms:  pricedTerms(tc.count),
			}})))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want refusal, got accepted=%d (terms count=%d)", resp.Msg.GetAccepted(), tc.count)
				}
				assertConnectCode(t, err, connect.CodeInvalidArgument)
				assertWireViolation(t, err, "entries[0].terms", "repeated.max_items")
			} else {
				if err != nil {
					t.Fatalf("push: %v", err)
				}
				if resp.Msg.GetAccepted() != 1 {
					t.Fatalf("accepted=%d, want 1 (terms count=%d)", resp.Msg.GetAccepted(), tc.count)
				}
			}
			if got := discoverOfferCount(t, h, "https://"+h.publisherDom+tc.path); got != tc.wantOffers {
				t.Fatalf("DiscoverResources offers = %d, want %d (persistence probe)", got, tc.wantOffers)
			}
		})
	}
}

// TestPushResources_TermsCapMixedBatch proves the refusal is whole-submission,
// not per-entry: a push carrying one within-cap entry and one over-cap entry is
// refused as a unit, and NEITHER URI becomes discoverable. The success leg
// pushes a within-cap entry alone first, so the zero offers on the failure leg
// are a refusal and not an entry that could never have stored. The violation
// names the second entry — entries[1].terms — which is the sibling that sank
// the batch; the within-cap first entry carries no violation of its own.
func TestPushResources_TermsCapMixedBatch(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)
	capacity := maxTermsPerEntry(t)

	const soloPath = "/cap/mixed-solo-valid"
	const validPath = "/cap/mixed-valid"
	const invalidPath = "/cap/mixed-over"

	// SUCCESS leg: the within-cap entry pushed ALONE is accepted + discoverable.
	solo, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: soloPath, Terms: pricedTerms(2)}})))
	if err != nil {
		t.Fatalf("solo within-cap push: %v", err)
	}
	if solo.Msg.GetAccepted() != 1 {
		t.Fatalf("solo within-cap accepted=%d, want 1", solo.Msg.GetAccepted())
	}
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+soloPath); got != 1 {
		t.Fatalf("solo within-cap offers = %d, want 1", got)
	}

	// FAILURE leg: within-cap + over-cap sibling → the whole submission is
	// refused at the wire; NEITHER persists.
	resp, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{
		{Domain: h.publisherDom, Path: validPath, Terms: pricedTerms(2)},
		{Domain: h.publisherDom, Path: invalidPath, Terms: pricedTerms(capacity + 1)},
	})))
	if err == nil {
		t.Fatalf("want whole-submission refusal, got accepted=%d", resp.Msg.GetAccepted())
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	assertWireViolation(t, err, "entries[1].terms", "repeated.max_items")
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+validPath); got != 0 {
		t.Fatalf("within-cap sibling offers = %d, want 0 (over-cap sibling sinks the submission)", got)
	}
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+invalidPath); got != 0 {
		t.Fatalf("over-cap entry offers = %d, want 0", got)
	}
}

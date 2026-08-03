//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// maxTermsPerEntryUnderTest pins the boundary the cap test drives to the
// production constant, so the test moves in lockstep with any future cap change
// rather than silently diverging from it.
const maxTermsPerEntryUnderTest = service.MaxTermsPerEntry

// TestPushResources_TermsCardinalityCap proves the terms-cardinality cap wired end-to-end through
// the public Connect surface: the terms[] array length on a single ResourceEntry
// is contributor-controlled at PushResources, and an entry carrying MORE than the
// cap is rejected as a PER-ENTRY verdict — never persisted — so the stored JSONB
// the discovery read path decodes can never grow without bound. A contributor
// cannot make one entry impose unbounded per-read decode CPU.
//
// The cap (service.MaxTermsPerEntry == 32) is the largest terms[] length an entry
// may carry; cap+1 is the smallest rejected size. Both the boundary-accept and
// boundary-reject cases are asserted entirely through the public surface:
// PushResources counts for the verdict, DiscoverResources offer-count for the
// persistence side effect (one offer ⇒ the entry reached the catalog, zero ⇒ it
// did not). No DB/repo/sqlc access (Testing Doctrine pt 9) — full protocol
// round-trip, push-RPC to read-RPC.
func TestPushResources_TermsCardinalityCap(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	// pricedEnumerated is the minimal valid term (passes licenseterm.Validate): each element of
	// the terms[] array is identical and individually valid, so the ONLY axis the
	// cap test exercises is array LENGTH, not per-term validity.
	pricedEnumerated := func() *rampv1.LicenseTerm {
		return &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String("accesses")},
		}
	}
	terms := func(n int) []*rampv1.LicenseTerm {
		out := make([]*rampv1.LicenseTerm, 0, n)
		for range n {
			out = append(out, pricedEnumerated())
		}
		return out
	}

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
			count:      maxTermsPerEntryUnderTest,
			wantOffers: 1,
		},
		{
			name:    "one over the cap is rejected and not persisted",
			path:    "/cap/over-limit",
			count:   maxTermsPerEntryUnderTest + 1,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
				TenantId: h.tenantID,
				CallerId: callerID,
				Entries: []*rampv1.ResourceEntry{{
					Domain: h.publisherDom,
					Path:   tc.path,
					Terms:  terms(tc.count),
				}},
			}))
			// All-or-nothing: an over-cap entry rejects the whole push.
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want rejection, got accepted=%d (terms count=%d)", resp.Msg.GetAccepted(), tc.count)
				}
				assertConnectCode(t, err, connect.CodeInvalidArgument)
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

// TestPushResources_TermsCapMixedBatch proves the cap reject is PER-ENTRY: a
// single push carrying one within-cap entry and one over-cap entry accepts
// exactly the within-cap one, and only its URI becomes discoverable. The
// over-cap entry rejecting must not abort the batch.
func TestPushResources_TermsCapMixedBatch(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const soloPath = "/cap/mixed-solo-valid"
	const validPath = "/cap/mixed-valid"
	const invalidPath = "/cap/mixed-over"

	priced := func(n int) []*rampv1.LicenseTerm {
		out := make([]*rampv1.LicenseTerm, 0, n)
		for range n {
			out = append(out, &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String("accesses")},
			})
		}
		return out
	}

	// SUCCESS leg: the within-cap entry pushed ALONE is accepted + discoverable.
	solo, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries:  []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: soloPath, Terms: priced(2)}},
	}))
	if err != nil {
		t.Fatalf("solo within-cap push: %v", err)
	}
	if solo.Msg.GetAccepted() != 1 {
		t.Fatalf("solo within-cap accepted=%d, want 1", solo.Msg.GetAccepted())
	}
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+soloPath); got != 1 {
		t.Fatalf("solo within-cap offers = %d, want 1", got)
	}

	// FAILURE leg: within-cap + over-cap sibling → whole push rejected; NEITHER persists.
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{
			{Domain: h.publisherDom, Path: validPath, Terms: priced(2)},
			{Domain: h.publisherDom, Path: invalidPath, Terms: priced(maxTermsPerEntryUnderTest + 1)},
		},
	}))
	if err == nil {
		t.Fatalf("want whole-request rejection, got accepted=%d", resp.Msg.GetAccepted())
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+validPath); got != 0 {
		t.Fatalf("within-cap sibling offers = %d, want 0 (over-cap sibling sinks the batch)", got)
	}
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+invalidPath); got != 0 {
		t.Fatalf("over-cap entry offers = %d, want 0", got)
	}
}

//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/proto"
)

// TestPushResources_NormalizeRoundTrip proves the ingest
// canonicalization end-to-end through the public Connect surface: a publisher
// PUSHES a term carrying non-canonical restriction tokens via
// CatalogService.PushResources, and the test observes the canonical tokens ONLY
// through DiscoverResources → Offer.terms. No DB/repo/sqlc access (Testing
// Doctrine pt 9) — this is a full protocol round-trip, push-RPC to read-RPC,
// across the resource→offer terms projection this slice adds.
func TestPushResources_NormalizeRoundTrip(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	// Every pushed term carries valid Pricing so it clears Validate
	// and reaches the catalog; the assertion is purely about token form.
	priced := &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.02", Currency: "USD", Unit: proto.String("accesses")}

	cases := []struct {
		name           string
		path           string
		kind           rampv1.RestrictionKind
		permitted      []string
		prohibited     []string
		wantPermitted  []string
		wantProhibited []string
	}{
		{
			name:          "function aliases canonicalize",
			path:          "/normalize/function",
			kind:          rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
			permitted:     []string{"generative-ai", "scrape"},
			wantPermitted: []string{"ai-input", "crawl"},
		},
		{
			name:           "function aliases canonicalize on prohibited",
			path:           "/normalize/function-prohibited",
			kind:           rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
			prohibited:     []string{"tdm", "copy"},
			wantProhibited: []string{"text-and-data-mining", "reproduce"},
		},
		{
			name:          "user-type aliases canonicalize",
			path:          "/normalize/user-type",
			kind:          rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE,
			permitted:     []string{"personal", "enterprise"},
			wantPermitted: []string{"individual", "commercial_entity"},
		},
		{
			// Wire-legal lowercase tokens uppercase at the RPC. Whitespace
			// trimming is deliberately NOT exercised here: the protovalidate
			// interceptor (restriction.permitted.format) rejects whitespace at the
			// wire before the handler canonicalizer runs, so a " de " pushed
			// directly through the RPC is contractually invalid (see the negative
			// in catalog_protovalidate_e2e_test.go). Whitespace trimming stays
			// proven at the unit level by licenseterm.TestNormalize.
			name:          "geography uppercases",
			path:          "/normalize/geography",
			kind:          rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
			permitted:     []string{"us", "de"},
			wantPermitted: []string{"US", "DE"},
		},
		{
			name:          "already-canonical tokens are unchanged (idempotent at ingest)",
			path:          "/normalize/canonical",
			kind:          rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
			permitted:     []string{"ai-input", "ai-train"},
			wantPermitted: []string{"ai-input", "ai-train"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			term := &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   priced,
				Restrictions: []*rampv1.Restriction{{
					Kind:       tc.kind,
					Permitted:  tc.permitted,
					Prohibited: tc.prohibited,
				}},
			}
			pushOneTerm(t, h, client, callerID, tc.path, term)

			gotTerms := discoverTerms(t, h, "https://"+h.publisherDom+tc.path)
			if len(gotTerms) != 1 {
				t.Fatalf("discovered terms = %d, want 1", len(gotTerms))
			}
			r := gotTerms[0].GetRestrictions()
			if len(r) != 1 {
				t.Fatalf("restrictions = %d, want 1", len(r))
			}
			assertStrs(t, "permitted", r[0].GetPermitted(), tc.wantPermitted)
			assertStrs(t, "prohibited", r[0].GetProhibited(), tc.wantProhibited)
		})
	}
}

// TestPushResources_NormalizeIdempotentRepush proves idempotency across a
// re-push: pushing canonical tokens that were already the normalized form of a
// prior push leaves the discoverable term unchanged. Observed entirely through
// the public surface.
func TestPushResources_NormalizeIdempotentRepush(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const path = "/normalize/repush"
	uri := "https://" + h.publisherDom + path
	priced := &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.02", Currency: "USD", Unit: proto.String("accesses")}
	mkTerm := func(permitted []string) *rampv1.LicenseTerm {
		return &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   priced,
			Restrictions: []*rampv1.Restriction{{
				Kind:      rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION,
				Permitted: permitted,
			}},
		}
	}

	// First push: alias form → canonical.
	pushOneTerm(t, h, client, callerID, path, mkTerm([]string{"generative-ai"}))
	first := discoverTerms(t, h, uri)
	assertStrs(t, "first permitted", first[0].GetRestrictions()[0].GetPermitted(), []string{"ai-input"})

	// Re-push the canonical form → unchanged.
	pushOneTerm(t, h, client, callerID, path, mkTerm([]string{"ai-input"}))
	second := discoverTerms(t, h, uri)
	assertStrs(t, "re-push permitted", second[0].GetRestrictions()[0].GetPermitted(), []string{"ai-input"})
}

// pushOneTerm pushes a single entry carrying one term and asserts it was
// accepted — the shared arrange step for the normalize scenarios.
func pushOneTerm(t *testing.T, h *pushHarness, client rampconnect.CatalogServiceClient, callerID, path string, term *rampv1.LicenseTerm) {
	t.Helper()
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom,
			Path:   path,
			Terms:  []*rampv1.LicenseTerm{term},
		}},
	}))
	if err != nil {
		t.Fatalf("push %s: %v", path, err)
	}
	if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
		t.Fatalf("push %s: accepted=%d rejected=%d, want 1/0", path, resp.Msg.GetAccepted(), resp.Msg.GetRejected())
	}
}

// discoverTerms reads the license terms an Exchange projects onto the single
// offer for uri — the public surface (DiscoverResources → Offer.terms) through
// which persisted, canonicalized terms become observable.
func discoverTerms(t *testing.T, h *pushHarness, uri string) []*rampv1.LicenseTerm {
	t.Helper()
	offers := discoverOffers(t, h, uri)
	if len(offers) != 1 {
		t.Fatalf("discover %s: offers = %d, want 1", uri, len(offers))
	}
	return offers[0].GetTerms()
}

// assertStrs compares two string slices order-sensitively with a readable diff.
func assertStrs(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v (len %d), want %v (len %d)", label, got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] = %q, want %q (full: %v)", label, i, got[i], want[i], got)
		}
	}
}

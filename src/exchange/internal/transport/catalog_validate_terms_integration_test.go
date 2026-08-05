//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/proto"
)

// TestPushResources_TermValidation proves the hard-reject wired
// end-to-end through the public Connect surface: a publisher PUSHES entries
// carrying license terms via CatalogService.PushResources, and the only thing
// the test observes is the RPC response counts plus what DiscoverResources
// makes visible afterward. A term with no Pricing is unactionable, so any
// entry carrying a priceless term — for EITHER semantics — must be rejected
// AND never persist; priced entries must persist.
//
// Persistence is observed solely through DiscoverResources offer-count: one
// offer means the entry reached the catalog, zero means it did not. The offer's
// own pricing is the catalog default and is unrelated to the pushed term — the
// COUNT proves persistence, nothing more. No DB/repo/sqlc access (Testing
// Doctrine pt 9): this is a full protocol round-trip, push-RPC to read-RPC.
func TestPushResources_TermValidation(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	enumerated := func(p *rampv1.Pricing) *rampv1.LicenseTerm {
		return &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: p}
	}

	const licDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	licensed := func(p *rampv1.Pricing, extra func(*rampv1.LicenseTerm)) *rampv1.LicenseTerm {
		term := &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
			License:   &rampv1.License{Uri: proto.String("https://example.com/license.txt"), UriDigest: proto.String(licDigest)},
			Pricing:   p,
		}
		if extra != nil {
			extra(term)
		}
		return term
	}
	perUnit := &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.02", Currency: "USD", Unit: proto.String("accesses")}

	// Shape rules (pricing-required, REFERENCE_ONLY⇒uri) are enforced by
	// protovalidate at the boundary => a violating push is rejected wholesale
	// (connect InvalidArgument), nothing persisted. No partial acceptance.
	cases := []struct {
		name       string
		path       string
		terms      []*rampv1.LicenseTerm
		wantErr    bool
		wantOffers int
	}{
		{
			name:    "ENUMERATED without pricing is rejected (protovalidate; nothing persisted)",
			path:    "/validate/enumerated-no-pricing",
			terms:   []*rampv1.LicenseTerm{enumerated(nil)},
			wantErr: true,
		},
		{
			name: "ENUMERATED with explicit FREE pricing is accepted and persisted",
			path: "/validate/enumerated-free",
			terms: []*rampv1.LicenseTerm{enumerated(&rampv1.Pricing{
				Model: rampv1.PricingModel_PRICING_MODEL_FREE, Currency: "USD",
			})},
			wantOffers: 1,
		},
		{
			name:    "REFERENCE_ONLY without pricing is rejected (protovalidate; nothing persisted)",
			path:    "/validate/reference-only-no-price",
			terms:   []*rampv1.LicenseTerm{{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, License: &rampv1.License{Uri: proto.String("https://example.com/license.txt"), UriDigest: proto.String(licDigest)}}},
			wantErr: true,
		},
		{
			name:       "REFERENCE_ONLY with pricing under a license is accepted and persisted",
			path:       "/validate/reference-only-priced",
			terms:      []*rampv1.LicenseTerm{licensed(perUnit, nil)},
			wantOffers: 1,
		},
		{
			name: "REFERENCE_ONLY carrying restrictions+quotas+obligations is accepted and persisted (advisory summary)",
			path: "/validate/reference-only-with-machine-fields",
			terms: []*rampv1.LicenseTerm{licensed(perUnit, func(term *rampv1.LicenseTerm) {
				term.Restrictions = []*rampv1.Restriction{{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}}}
				term.Quotas = []*rampv1.Quota{{Metric: "tokens", Limit: 100, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
				term.Obligations = []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}}
			})},
			wantOffers: 1,
		},
		{
			name:    "REFERENCE_ONLY referencing no license is rejected (protovalidate; nothing persisted)",
			path:    "/validate/reference-only-no-license",
			terms:   []*rampv1.LicenseTerm{{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, Pricing: perUnit}},
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
					Terms:  tc.terms,
				}},
			}))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want rejection, got accepted=%d", resp.Msg.GetAccepted())
				}
				assertConnectCode(t, err, connect.CodeInvalidArgument)
			} else {
				if err != nil {
					t.Fatalf("push: %v", err)
				}
				if resp.Msg.GetAccepted() != int32(len(tc.terms)) {
					t.Fatalf("accepted=%d, want %d", resp.Msg.GetAccepted(), len(tc.terms))
				}
			}
			if got := discoverOfferCount(t, h, "https://"+h.publisherDom+tc.path); got != tc.wantOffers {
				t.Fatalf("DiscoverResources offers = %d, want %d (persistence probe)", got, tc.wantOffers)
			}
		})
	}
}

// TestPushResources_TermValidationMixedBatch proves the push is ALL-OR-NOTHING:
// a single push carrying one valid and one structurally-invalid entry is
// rejected wholesale (no partial acceptance), and NEITHER URI becomes
// discoverable. Asserted entirely through the public surface.
func TestPushResources_TermValidationMixedBatch(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	const soloPath = "/validate/mixed-solo-valid"
	const validPath = "/validate/mixed-valid"
	const invalidPath = "/validate/mixed-invalid"

	validTerm := func() *rampv1.LicenseTerm {
		return &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String("accesses")},
		}
	}

	// SUCCESS leg: the valid entry pushed ALONE is accepted and discoverable —
	// proving it is well-formed, so the batch rejection below is caused by the
	// bad sibling, not the good entry.
	solo, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries:  []*rampv1.ResourceEntry{{Domain: h.publisherDom, Path: soloPath, Terms: []*rampv1.LicenseTerm{validTerm()}}},
	}))
	if err != nil {
		t.Fatalf("solo valid push: %v", err)
	}
	if solo.Msg.GetAccepted() != 1 {
		t.Fatalf("solo valid accepted=%d, want 1", solo.Msg.GetAccepted())
	}
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+soloPath); got != 1 {
		t.Fatalf("solo valid offers = %d, want 1", got)
	}

	// FAILURE leg: the same valid entry + a structurally-invalid sibling
	// (ENUMERATED without pricing) → whole submission rejected at the
	// protovalidate boundary, NEITHER URL persists. No partial acceptance.
	resp, err := client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{
			{Domain: h.publisherDom, Path: validPath, Terms: []*rampv1.LicenseTerm{validTerm()}},
			{Domain: h.publisherDom, Path: invalidPath, Terms: []*rampv1.LicenseTerm{{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED}}},
		},
	}))
	if err == nil {
		t.Fatalf("want whole-request rejection, got accepted=%d", resp.Msg.GetAccepted())
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+validPath); got != 0 {
		t.Fatalf("valid sibling offers = %d, want 0 (bad sibling sinks the batch)", got)
	}
	if got := discoverOfferCount(t, h, "https://"+h.publisherDom+invalidPath); got != 0 {
		t.Fatalf("invalid entry offers = %d, want 0", got)
	}
}

// TestPushResources_RuleAudit proves the licenseterm-owned rules — the
// ones protovalidate does NOT cover — wired end-to-end through PushResources.
// Each HARD case must be rejected and leave zero discoverable offers; the matrix
// is asserted entirely through the public RPC surface, never a struct call. The
// baseline term is ENUMERATED with valid per-access pricing so only the
// rule-under-test trips. (protovalidate-owned structural rejects are out of
// scope: this test only exercises the licenseterm layer.)
func TestPushResources_RuleAudit(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	pricing := &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String("accesses")}
	base := func(mutate func(*rampv1.LicenseTerm)) *rampv1.LicenseTerm {
		term := &rampv1.LicenseTerm{Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: pricing}
		mutate(term)
		return term
	}

	cases := []struct {
		name string
		path string
		term *rampv1.LicenseTerm
	}{
		// REFERENCE_ONLY carrying restrictions/quotas/obligations is now ACCEPTED
		// (flexible model, ADR-014): machine fields are an advisory readable
		// summary of the referenced document. The accepted+persisted assertion
		// lives in TestPushResources_TermValidation; the broad E2E demonstration
		// across JSONL inputs is a separate follow-up.
		{
			name: "quota with non-positive limit is rejected",
			path: "/audit/quota-zero-limit",
			term: base(func(t *rampv1.LicenseTerm) {
				t.Quotas = []*rampv1.Quota{{Metric: "tokens", Limit: 0, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
			}),
		},
		{
			name: "quota with unregistered bare metric is rejected",
			path: "/audit/quota-bad-metric",
			term: base(func(t *rampv1.LicenseTerm) {
				t.Quotas = []*rampv1.Quota{{Metric: "frobnications", Limit: 10, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}}
			}),
		},
		{
			// validatePricingUnitMembership (licenseterm.go:107-116): a bare
			// (non-namespaced) Pricing.unit that is not a registered metering token
			// is a hard reject. A fresh Pricing is assigned (never the shared base
			// pointer) so only this rule trips.
			name: "pricing unit unregistered bare token is rejected",
			path: "/audit/pricing-unit-bad",
			term: base(func(t *rampv1.LicenseTerm) {
				t.Pricing = &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String("frobnications")}
			}),
		},
		{
			name: "duplicate restriction kind is rejected",
			path: "/audit/dup-restriction",
			term: base(func(t *rampv1.LicenseTerm) {
				t.Restrictions = []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}},
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"search"}},
				}
			}),
		},
		{
			name: "permitted and prohibited overlap is rejected",
			path: "/audit/restriction-overlap",
			term: base(func(t *rampv1.LicenseTerm) {
				t.Restrictions = []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}, Prohibited: []string{"ai-train"}},
				}
			}),
		},
		{
			name: "share-alike obligation without scope_license is rejected",
			path: "/audit/sharealike-no-scope",
			term: base(func(t *rampv1.LicenseTerm) {
				// Trigger is required (protovalidate: unset trigger is rejected at
				// ingest); set it so the rejection under test is the missing
				// scope_license rule, not the trigger guard.
				t.Obligations = []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_SHARE_ALIKE, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_DISTRIBUTION}}
			}),
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
					Terms:  []*rampv1.LicenseTerm{tc.term},
				}},
			}))
			// All-or-nothing: a coherence-invalid term rejects the whole
			// submission with InvalidArgument; nothing persists.
			if err == nil {
				t.Fatalf("want rejection, got accepted=%d", resp.Msg.GetAccepted())
			}
			assertConnectCode(t, err, connect.CodeInvalidArgument)
			if got := discoverOfferCount(t, h, "https://"+h.publisherDom+tc.path); got != 0 {
				t.Fatalf("DiscoverResources offers = %d, want 0 (rejected term must not persist)", got)
			}
		})
	}
}

// TestPushResources_LintWarnings proves the LINT classification through
// PushResources: an unregistered restriction token and an OTHER obligation
// without detail are NON-fatal — the term is ACCEPTED (one discoverable offer)
// and the issue is surfaced in PushResourcesResponse.warnings[]. Membership is
// decoupled from the Restriction.advisory flag (scope-only projection: the
// Exchange never evaluates restrictions, so an unknown token can only warrant a
// lint flag, never a reject). This is the only path that asserts the warnings[]
// field, the membership-as-lint half of the classification.
func TestPushResources_LintWarnings(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	pricing := &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String("accesses")}

	cases := []struct {
		name        string
		path        string
		term        *rampv1.LicenseTerm
		wantWarning string
	}{
		{
			name: "unregistered token on binding restriction warns but accepts",
			path: "/audit/lint-unknown-token",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   pricing,
				Restrictions: []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"flibbertigibbet"}, Advisory: false},
				},
			},
			wantWarning: "flibbertigibbet",
		},
		{
			name: "OTHER obligation without detail warns but accepts",
			path: "/audit/lint-other-obligation",
			term: &rampv1.LicenseTerm{
				Semantics:   rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:     pricing,
				Obligations: []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_OTHER, Trigger: rampv1.ObligationTrigger_OBLIGATION_TRIGGER_ON_USE}},
			},
			wantWarning: "OTHER",
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
					Terms:  []*rampv1.LicenseTerm{tc.term},
				}},
			}))
			if err != nil {
				t.Fatalf("push: %v", err)
			}
			if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
				t.Fatalf("accepted=%d rejected=%d, want 1/0 (lint is non-fatal)", resp.Msg.GetAccepted(), resp.Msg.GetRejected())
			}
			if !warningsContain(resp.Msg.GetWarnings(), tc.wantWarning) {
				t.Fatalf("warnings = %v, want one containing %q", resp.Msg.GetWarnings(), tc.wantWarning)
			}
			if got := discoverOfferCount(t, h, "https://"+h.publisherDom+tc.path); got != 1 {
				t.Fatalf("DiscoverResources offers = %d, want 1 (accepted term persists)", got)
			}
		})
	}
}

// TestPushResources_PricingUnitAccepted is the positive half of the pricing-unit
// membership rule (validatePricingUnitMembership): the units that are NOT
// hard-rejected must be accepted and become discoverable. A bare token that IS a
// registered metering unit ("accesses") passes membership, and any namespaced
// vendor unit ("acme:widgets") is a deliberate custom unit that skips the
// membership check entirely. Both are asserted through PushResources counts +
// DiscoverResources offer count — the same single surface as the reject path.
func TestPushResources_PricingUnitAccepted(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	enumeratedWithUnit := func(unit string) *rampv1.LicenseTerm {
		return &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD", Unit: proto.String(unit)},
		}
	}

	cases := []struct {
		name string
		path string
		unit string
	}{
		{
			name: "bare registered metering unit is accepted",
			path: "/audit/pricing-unit-registered",
			unit: "accesses",
		},
		{
			name: "namespaced vendor unit skips membership and is accepted",
			path: "/audit/pricing-unit-namespaced",
			unit: "acme:widgets",
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
					Terms:  []*rampv1.LicenseTerm{enumeratedWithUnit(tc.unit)},
				}},
			}))
			if err != nil {
				t.Fatalf("push: %v", err)
			}
			if resp.Msg.GetAccepted() != 1 || resp.Msg.GetRejected() != 0 {
				t.Fatalf("accepted=%d rejected=%d, want 1/0 (unit %q is valid)", resp.Msg.GetAccepted(), resp.Msg.GetRejected(), tc.unit)
			}
			if got := discoverOfferCount(t, h, "https://"+h.publisherDom+tc.path); got != 1 {
				t.Fatalf("DiscoverResources offers = %d, want 1 (accepted term persists)", got)
			}
		})
	}
}

func warningsContain(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// setupTermContributor registers callerID as a catalog contributor with a
// self-signup agent manifest and returns a catalog client that signs as that
// caller — the standard admitted-contributor bring-up the term-validation
// scenarios share.
func setupTermContributor(t *testing.T, h *pushHarness, callerID string) rampconnect.CatalogServiceClient {
	t.Helper()
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen caller key: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	return h.signedCat(callerID, priv)
}

// discoverOffers returns the offers DiscoverResources yields for uri. It is the
// shared public read primitive the term-observation helpers build on: every
// term assertion in this package reads back through this RPC, never the DB.
func discoverOffers(t *testing.T, h *pushHarness, uri string) []*rampv1.Offer {
	t.Helper()
	return discoverOffersAs(t, h, uri, requesterWithScopes("agent-discover"))
}

// discoverOfferCount returns how many offers DiscoverResources yields for uri.
// It is the public persistence probe: a pushed entry that reached the catalog
// resolves to one offer, an entry that was rejected resolves to zero.
func discoverOfferCount(t *testing.T, h *pushHarness, uri string) int {
	t.Helper()
	return len(discoverOffers(t, h, uri))
}

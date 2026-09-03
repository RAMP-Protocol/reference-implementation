//go:build integration

package transport_test

import (
	"fmt"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// scopedTerm builds an ENUMERATED term whose only gating is scope coverage: no
// machine restrictions, a minimal valid Pricing, and the given term scopes. The
// scope helpers live here (the single home for the scope family) and reuse the
// shared selectPricing/labels/assertStrs helpers per the epic Design (Doctrine
// pt7) — promote them only when a second file needs them.
func scopedTerm(label string, scopes ...string) *rampv1.LicenseTerm {
	l := label
	return &rampv1.LicenseTerm{
		Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
		Pricing:   selectPricing(),
		PartLabel: &l,
		Scopes:    scopes,
	}
}

// requesterWithScopes builds a Requester carrying the Biscuit-authority scopes
// selectTerms reads from the native Requester.scopes field (distinct from the
// ext facets requesterWithExt populates). No user_type/geography facets are set, so
// a scope-only term — which carries no restrictions — is gated purely on scope
// coverage.
func requesterWithScopes(id string, scopes ...string) requesterSpec {
	return requesterSpec{requester: newRequester(id, "agent.example", scopes...)}
}

// TestDiscover_SelectByScope pins scope/subscription gating
// (service/termselect.go: selectTerms -> scopesCovered/scopeCovered) through
// the public DiscoverResources RPC, the single observation surface. Each row
// pushes ONE scope-gated term and discovers it as a requester with a given
// Biscuit-authority scope set; a kept term projects on a single offer with the
// exact part_label, an uncovered term yields NO offer (all-terms-filtered =>
// no eligible priced term => no offer — never an empty-terms stub).
//
// The matrix exercises every branch of scopeCovered: exact equality, the global
// "*", the hierarchical "prefix:*", scope-insufficient exclusion, and the
// AND-coverage requirement of scopesCovered (every term scope must be covered).
func TestDiscover_SelectByScope(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	cases := []struct {
		name       string
		path       string
		termScopes []string
		reqScopes  []string
		keep       bool
	}{
		{
			name:       "exact: requester dist:US covers term dist:US (scopeCovered exact)",
			path:       "/scope/exact",
			termScopes: []string{"dist:US"},
			reqScopes:  []string{"dist:US"},
			keep:       true,
		},
		{
			name:       "absent: requester with no scope cannot cover term dist:US (scopeCovered)",
			path:       "/scope/absent",
			termScopes: []string{"dist:US"},
			reqScopes:  nil,
			keep:       false,
		},
		{
			name:       "hierarchical: requester dist:* covers term dist:US (scopeCovered prefix)",
			path:       "/scope/hierarchical",
			termScopes: []string{"dist:US"},
			reqScopes:  []string{"dist:*"},
			keep:       true,
		},
		{
			name:       "global: requester * covers term dist:US (scopeCovered global)",
			path:       "/scope/global",
			termScopes: []string{"dist:US"},
			reqScopes:  []string{"*"},
			keep:       true,
		},
		{
			name:       "AND-coverage partial: dist:* alone cannot cover [dist:US, sub:premium] (scopesCovered)",
			path:       "/scope/and-partial",
			termScopes: []string{"dist:US", "sub:premium"},
			reqScopes:  []string{"dist:*"},
			keep:       false,
		},
		{
			name:       "AND-coverage full: dist:* + sub:premium cover [dist:US, sub:premium] (scopesCovered)",
			path:       "/scope/and-full",
			termScopes: []string{"dist:US", "sub:premium"},
			reqScopes:  []string{"dist:*", "sub:premium"},
			keep:       true,
		},
		{
			name:       "public: empty term scopes are covered for a scopeless requester (scopesCovered public)",
			path:       "/scope/public",
			termScopes: nil,
			reqScopes:  nil,
			keep:       true,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uri := "https://" + h.publisherDom + tc.path
			pushTerms(t, h, client, callerID, tc.path, scopedTerm("scoped", tc.termScopes...))
			req := requesterWithScopes(fmt.Sprintf("agent-scope-%d", i), tc.reqScopes...)

			if tc.keep {
				got := discoverTermsAs(t, h, uri, req)
				assertStrs(t, tc.name, labels(got), []string{"scoped"})
				return
			}
			if offers := discoverOffersAs(t, h, uri, req); len(offers) != 0 {
				t.Fatalf("%s: offers = %d, want 0 (scope-insufficient => no eligible priced term => no offer)", tc.name, len(offers))
			}
		})
	}
}

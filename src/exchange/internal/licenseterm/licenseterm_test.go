package licenseterm_test

import (
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/licenseterm"
)

// TestValidateHardReject covers the hard-reject rule across the full
// semantics x Pricing grid: a term with no Pricing is unactionable for an
// agent, so Pricing is REQUIRED on EVERY term regardless of semantics —
// including REFERENCE_ONLY (whose License governs human-readable terms but does
// not replace the machine-readable price). model=FREE must be explicit: an
// absent Pricing is NOT free, which falls straight out of the nil-Pricing check
// (a present Pricing{model=FREE} passes; an absent one fails). The License
// field is varied to prove it does not substitute for Pricing. Warnings are
// deferred to a later slice, so every case asserts zero warnings.
func TestValidateHardReject(t *testing.T) {
	vocab := licenseterm.NewInMemoryVocab()

	pricing := func(model rampv1.PricingModel) *rampv1.Pricing {
		return &rampv1.Pricing{Model: model, Rate: "0.07", Currency: "USD"}
	}
	licenseURI := &rampv1.License{Uri: proto.String("https://example.com/license.txt")}

	cases := []struct {
		name    string
		term    *rampv1.LicenseTerm
		wantErr bool
	}{
		// NOTE: pricing-required and REFERENCE_ONLY⇒uri presence checks moved to
		// protovalidate (proto CEL) at the RPC boundary; their coverage lives in
		// the transport boundary test, not this unit suite.
		{
			name: "ENUMERATED with per-access Pricing is accepted",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   pricing(rampv1.PricingModel_PRICING_MODEL_PER_UNIT),
			},
			wantErr: false,
		},
		{
			name: "ENUMERATED with explicit FREE Pricing is accepted",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   pricing(rampv1.PricingModel_PRICING_MODEL_FREE),
			},
			wantErr: false,
		},
		{
			name: "REFERENCE_ONLY with Pricing and License is accepted",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
				License:   licenseURI,
				Pricing:   pricing(rampv1.PricingModel_PRICING_MODEL_PER_UNIT),
			},
			wantErr: false,
		},
		{
			name: "REFERENCE_ONLY with explicit FREE Pricing under a license is accepted",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
				License:   licenseURI,
				Pricing:   pricing(rampv1.PricingModel_PRICING_MODEL_FREE),
			},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warnings, err := licenseterm.Validate(tc.term, vocab)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate err = %v, wantErr = %v", err, tc.wantErr)
			}
			if len(warnings) != 0 {
				t.Fatalf("warnings = %v, want none (warnings deferred to a later slice)", warnings)
			}
		})
	}
}

// pricing returns a valid per-access Pricing — the baseline every non-pricing
// rule under test reuses so it does not trip the "pricing required" hard reject.
func validPricing() *rampv1.Pricing {
	return &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.07", Currency: "USD"}
}

// TestValidateMatrix is the licenseterm-rules combination matrix realized as a test grid:
// each licenseterm-OWNED rule (the ones protovalidate does NOT cover) is proven
// either as a hard reject (wantErr) or a lint warning (wantWarning substring,
// term accepted). Tokens are fed already-canonical (as Normalize would leave
// them) so the permitted∩prohibited and membership checks are exercised exactly
// as the handler sees them. protovalidate-owned structural rules (token format,
// PER_UNIT⇒unit, FREE⇒rate0, enum sentinels) are deliberately NOT tested here —
// they are asserted at the RPC boundary, not in this layer.
func TestValidateMatrix(t *testing.T) {
	vocab := licenseterm.NewInMemoryVocab()
	licenseURI := &rampv1.License{Uri: proto.String("https://example.com/license.txt")}

	enumerated := func(mutate func(t *rampv1.LicenseTerm)) *rampv1.LicenseTerm {
		t := &rampv1.LicenseTerm{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing:   validPricing(),
		}
		mutate(t)
		return t
	}

	cases := []struct {
		name        string
		term        *rampv1.LicenseTerm
		wantErr     bool
		wantWarning string // substring expected in warnings when accepted
	}{
		// --- REFERENCE_ONLY × {restrictions, quotas, obligations}: PERMITTED ---
		// Machine fields are an advisory readable summary of the referenced
		// document; they are validated/canonicalized like any ENUMERATED term,
		// never stripped (flexible model, ADR-014).
		{
			name: "REFERENCE_ONLY with restrictions is accepted (advisory summary)",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
				License:   licenseURI,
				Pricing:   validPricing(),
				Restrictions: []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}},
				},
			},
			wantErr: false,
		},
		{
			name: "REFERENCE_ONLY with quotas is accepted (advisory summary)",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
				License:   licenseURI,
				Pricing:   validPricing(),
				Quotas:    []*rampv1.Quota{{Metric: "tokens", Limit: 100, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}},
			},
			wantErr: false,
		},
		{
			name: "REFERENCE_ONLY with obligations is accepted (advisory summary)",
			term: &rampv1.LicenseTerm{
				Semantics:   rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
				License:     licenseURI,
				Pricing:     validPricing(),
				Obligations: []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION}},
			},
			wantErr: false,
		},
		{
			name: "REFERENCE_ONLY with restrictions + quotas + obligations together is accepted",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
				License:   licenseURI,
				Pricing:   validPricing(),
				Restrictions: []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}},
				},
				Quotas:      []*rampv1.Quota{{Metric: "tokens", Limit: 100, Window: rampv1.QuotaWindow_QUOTA_WINDOW_DAILY}},
				Obligations: []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_ATTRIBUTION}},
			},
			wantErr: false,
		},
		{
			name: "REFERENCE_ONLY bare (license+pricing only) is accepted",
			term: &rampv1.LicenseTerm{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY,
				License:   licenseURI,
				Pricing:   validPricing(),
			},
			wantErr: false,
		},

		// --- Quota metric membership (limit ≥ 1 is protovalidate's now) ---
		{
			name:    "quota with unregistered bare metric is rejected (membership=hard)",
			term:    enumerated(func(t *rampv1.LicenseTerm) { t.Quotas = []*rampv1.Quota{{Metric: "frobnications", Limit: 10}} }),
			wantErr: true,
		},
		{
			name:    "quota with registered metric and positive limit is accepted",
			term:    enumerated(func(t *rampv1.LicenseTerm) { t.Quotas = []*rampv1.Quota{{Metric: "tokens", Limit: 10}} }),
			wantErr: false,
		},
		{
			name:    "quota with vendor-namespaced metric bypasses membership",
			term:    enumerated(func(t *rampv1.LicenseTerm) { t.Quotas = []*rampv1.Quota{{Metric: "acme:widgets", Limit: 10}} }),
			wantErr: false,
		},

		// Coherence (duplicate kind, permitted∩prohibited disjoint) is
		// protovalidate's now — exercised at the RPC boundary, not here.
		{
			name: "distinct restriction kinds with disjoint tokens are accepted",
			term: enumerated(func(t *rampv1.LicenseTerm) {
				t.Restrictions = []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}, Prohibited: []string{"search"}},
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, Permitted: []string{"US"}},
				}
			}),
			wantErr: false,
		},

		// --- Restriction token membership: always a lint warning, never a hard
		// reject, decoupled from the advisory/binding flag (scope-only projection
		// means the Exchange never evaluates restrictions; an unknown token can
		// only warrant a lint flag, never gate access). ---
		{
			name: "unregistered token on advisory restriction is a warning",
			term: enumerated(func(t *rampv1.LicenseTerm) {
				t.Restrictions = []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"flibbertigibbet"}, Advisory: true},
				}
			}),
			wantErr:     false,
			wantWarning: "flibbertigibbet",
		},
		{
			name: "unregistered token on binding restriction also only warns (membership decoupled from binding)",
			term: enumerated(func(t *rampv1.LicenseTerm) {
				t.Restrictions = []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"flibbertigibbet"}, Advisory: false},
				}
			}),
			wantErr:     false,
			wantWarning: "flibbertigibbet",
		},
		{
			name: "registered token on binding restriction is accepted cleanly",
			term: enumerated(func(t *rampv1.LicenseTerm) {
				t.Restrictions = []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, Permitted: []string{"ai-train"}, Advisory: false},
				}
			}),
			wantErr: false,
		},
		{
			name: "vendor-namespaced token bypasses membership on any axis",
			term: enumerated(func(t *rampv1.LicenseTerm) {
				t.Restrictions = []*rampv1.Restriction{
					{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_OTHER, Permitted: []string{"acme:custom-use"}, Advisory: false},
				}
			}),
			wantErr: false,
		},

		// SHARE_ALIKE ⇒ scope_license is protovalidate's now (boundary), not here.
		// --- Obligation: OTHER warning ---
		{
			name: "OTHER obligation without detail is a warning",
			term: enumerated(func(t *rampv1.LicenseTerm) {
				t.Obligations = []*rampv1.Obligation{{Kind: rampv1.ObligationKind_OBLIGATION_KIND_OTHER}}
			}),
			wantErr:     false,
			wantWarning: "OTHER",
		},
		{
			name: "OTHER obligation with detail is accepted cleanly",
			term: enumerated(func(t *rampv1.LicenseTerm) {
				t.Obligations = []*rampv1.Obligation{{
					Kind:   rampv1.ObligationKind_OBLIGATION_KIND_OTHER,
					Detail: proto.String("see appendix B"),
				}}
			}),
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warnings, err := licenseterm.Validate(tc.term, vocab)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if tc.wantWarning == "" {
				if len(warnings) != 0 {
					t.Fatalf("warnings = %v, want none", warnings)
				}
				return
			}
			if !containsSubstring(warnings, tc.wantWarning) {
				t.Fatalf("warnings = %v, want one containing %q", warnings, tc.wantWarning)
			}
		})
	}
}

func containsSubstring(items []string, sub string) bool {
	for _, s := range items {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// TestNormalize covers the token canonicalization across every
// restriction axis. Normalize rewrites permitted[]/prohibited[] in place:
// FUNCTION and USER_TYPE are trimmed+lowercased then alias-resolved; GEOGRAPHY
// is trimmed+uppercased with no aliases; OTHER is left untouched. The matrix
// also pins idempotency (the load-bearing property for re-pushes) and
// nil/empty safety.
func TestNormalize(t *testing.T) {
	restriction := func(kind rampv1.RestrictionKind, permitted, prohibited []string) *rampv1.LicenseTerm {
		return &rampv1.LicenseTerm{
			Restrictions: []*rampv1.Restriction{{
				Kind:       kind,
				Permitted:  permitted,
				Prohibited: prohibited,
			}},
		}
	}

	cases := []struct {
		name           string
		term           *rampv1.LicenseTerm
		wantPermitted  []string
		wantProhibited []string
	}{
		{
			name:          "function aliases resolve on permitted",
			term:          restriction(rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, []string{"generative-ai", "train-ai", "tdm"}, nil),
			wantPermitted: []string{"ai-input", "ai-train", "text-and-data-mining"},
		},
		{
			name:           "function aliases resolve on prohibited too",
			term:           restriction(rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, nil, []string{"scrape", "copy", "adapt", "derivative"}),
			wantProhibited: []string{"crawl", "reproduce", "modify", "modify"},
		},
		{
			name:          "function case+whitespace folded before alias lookup",
			term:          restriction(rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, []string{"  Generative-AI ", "AI-INPUT"}, nil),
			wantPermitted: []string{"ai-input", "ai-input"},
		},
		{
			name:          "user-type aliases resolve",
			term:          restriction(rampv1.RestrictionKind_RESTRICTION_KIND_USER_TYPE, []string{"personal", "business", "enterprise"}, nil),
			wantPermitted: []string{"individual", "commercial_entity", "commercial_entity"},
		},
		{
			name:          "geography uppercases, no aliasing",
			term:          restriction(rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, []string{"us", " de ", "eu", "*"}, nil),
			wantPermitted: []string{"US", "DE", "EU", "*"},
		},
		{
			name:          "OTHER axis is left untouched",
			term:          restriction(rampv1.RestrictionKind_RESTRICTION_KIND_OTHER, []string{"Custom-Token", "  Spaced  "}, nil),
			wantPermitted: []string{"Custom-Token", "  Spaced  "},
		},
		{
			name:          "unknown function token only case-folds",
			term:          restriction(rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION, []string{"Search", "Display"}, nil),
			wantPermitted: []string{"search", "display"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			licenseterm.Normalize(tc.term)
			assertTokens(t, "permitted", tc.term.GetRestrictions()[0].GetPermitted(), tc.wantPermitted)
			assertTokens(t, "prohibited", tc.term.GetRestrictions()[0].GetProhibited(), tc.wantProhibited)

			// Idempotency: a second pass must leave the canonical form unchanged.
			licenseterm.Normalize(tc.term)
			assertTokens(t, "permitted (idempotent)", tc.term.GetRestrictions()[0].GetPermitted(), tc.wantPermitted)
			assertTokens(t, "prohibited (idempotent)", tc.term.GetRestrictions()[0].GetProhibited(), tc.wantProhibited)
		})
	}
}

// TestNormalizeNilSafe pins that Normalize tolerates a nil term and a term with
// no restrictions without panicking — the handler calls it on every pushed
// term, including bare ones.
func TestNormalizeNilSafe(t *testing.T) {
	licenseterm.Normalize(nil)
	licenseterm.Normalize(&rampv1.LicenseTerm{})
	licenseterm.Normalize(&rampv1.LicenseTerm{
		Restrictions: []*rampv1.Restriction{{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION}},
	})
}

func assertTokens(t *testing.T, label string, got, want []string) {
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

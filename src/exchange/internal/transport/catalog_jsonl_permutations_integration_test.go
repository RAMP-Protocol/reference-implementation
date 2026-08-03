//go:build integration

package transport_test

import (
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// TestIngest_LicenseShapePermutations drives the full license-shape permutation
// matrix through the REAL publisher interface — JSON-L feed → ParseJSONL →
// MapRecords → RFC 9421-signed PushResources → DiscoverResources — against a
// real Exchange + testcontainers Postgres, with the protovalidate interceptor
// wired exactly as production.
//
// The matrix crosses the dimensions the proto bump expanded:
//   - semantics: ENUMERATED vs REFERENCE_ONLY
//   - license: absent | uri+digest | uri WITHOUT digest (invalid)
//   - machine fields (functions/quotas): present vs absent
//   - pricing: FREE | PER_UNIT | absent (invalid)
//
// Valid shapes must ingest and be discoverable with their machine fields
// carried (proving REFERENCE_ONLY is FLEXIBLE: enums ride alongside the license
// reference, not stripped). Invalid shapes must be rejected — uri-without-digest
// and REFERENCE_ONLY-without-uri at the protovalidate boundary (whole-submission
// reject, nothing persisted, no partial acceptance); absent-pricing at the
// mapper. A rejected shape must leave NOTHING discoverable.
func TestIngest_LicenseShapePermutations(t *testing.T) {
	h := newPushHarness(t)
	const domain = "publisher.example"
	kid, priv := registerContributor(t, h, domain)
	tenant := seedTenantForDomain(t, h, domain)

	const digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	lic := `"license":{"id":"perm","uri":"https://ex.example/lic","uri_digest":"` + digest + `","name":"Perm"},`
	licNoDigest := `"license":{"id":"perm","uri":"https://ex.example/lic","name":"Perm"},`
	free := `"pricing":{"model":"free","rate":"0","currency":"USD"}`
	paid := `"pricing":{"model":"per_unit","unit":"accesses","rate":"0.02","currency":"USD"}`
	badRate := `"pricing":{"model":"flat","rate":"abc","currency":"USD"}`
	freeNonZero := `"pricing":{"model":"free","rate":"0.05","currency":"USD"}`
	numericRate := `"pricing":{"model":"per_unit","unit":"accesses","rate":0.02,"currency":"USD"}`
	fns := `"functions":["ai-train"],`
	quota := `"quotas":[{"metric":"accesses","limit":500,"window":"daily"}],`

	rec := func(path, license, term string) string {
		return `{"domain":"` + domain + `","path":"` + path + `","title":"t",` + license + `"terms":[{` + term + `}]}`
	}

	cases := []struct {
		name     string
		path     string
		record   string
		wantErr  bool   // rejected at mapper OR protovalidate boundary
		wantFn   string // FUNCTION permitted token expected on the projected term ("" = none)
		wantRate string // Pricing.rate expected on the projected term (round-trip proof; "" = skip)
	}{
		// --- valid: ENUMERATED ---
		{
			name: "ENUMERATED / no-license / FREE / machine-fields", path: "/perm/enum-nolic-free-mf",
			record: rec("/perm/enum-nolic-free-mf", "", `"semantics":"enumerated",`+fns+free), wantFn: "ai-train", wantRate: "0",
		},
		{
			name: "ENUMERATED / no-license / PER_UNIT / bare", path: "/perm/enum-nolic-paid-bare",
			record: rec("/perm/enum-nolic-paid-bare", "", `"semantics":"enumerated",`+paid), wantRate: "0.02",
		},
		{
			name: "ENUMERATED / uri+digest / FREE / machine-fields", path: "/perm/enum-lic-free-mf",
			record: rec("/perm/enum-lic-free-mf", lic, `"semantics":"enumerated",`+fns+quota+free), wantFn: "ai-train", wantRate: "0",
		},
		{
			name: "ENUMERATED / uri+digest / PER_UNIT / bare", path: "/perm/enum-lic-paid-bare",
			record: rec("/perm/enum-lic-paid-bare", lic, `"semantics":"enumerated",`+paid), wantRate: "0.02",
		},
		// --- valid: REFERENCE_ONLY (flexible: enums permitted alongside the doc) ---
		{
			name: "REFERENCE_ONLY / uri+digest / FREE / bare", path: "/perm/ref-lic-free-bare",
			record: rec("/perm/ref-lic-free-bare", lic, `"semantics":"reference_only",`+free), wantRate: "0",
		},
		{
			name: "REFERENCE_ONLY / uri+digest / PER_UNIT / machine-fields", path: "/perm/ref-lic-paid-mf",
			record: rec("/perm/ref-lic-paid-mf", lic, `"semantics":"reference_only",`+fns+quota+paid), wantFn: "ai-train", wantRate: "0.02",
		},
		{
			name: "REFERENCE_ONLY / uri+digest / FREE / machine-fields", path: "/perm/ref-lic-free-mf",
			record: rec("/perm/ref-lic-free-mf", lic, `"semantics":"reference_only",`+fns+free), wantFn: "ai-train", wantRate: "0",
		},
		// --- invalid: uri WITHOUT digest (protovalidate license.digest_required_with_uri) ---
		{
			name: "ENUMERATED / uri-no-digest / FREE -> reject", path: "/perm/enum-nodigest",
			record: rec("/perm/enum-nodigest", licNoDigest, `"semantics":"enumerated",`+free), wantErr: true,
		},
		{
			name: "REFERENCE_ONLY / uri-no-digest / FREE -> reject", path: "/perm/ref-nodigest",
			record: rec("/perm/ref-nodigest", licNoDigest, `"semantics":"reference_only",`+free), wantErr: true,
		},
		// --- invalid: REFERENCE_ONLY without a license (protovalidate reference_only.requires_uri) ---
		{
			name: "REFERENCE_ONLY / no-license / FREE -> reject", path: "/perm/ref-nolic",
			record: rec("/perm/ref-nolic", "", `"semantics":"reference_only",`+free), wantErr: true,
		},
		// --- invalid: absent pricing (mapper requires pricing on every term) ---
		{
			name: "ENUMERATED / no-pricing -> reject", path: "/perm/enum-noprice",
			record: rec("/perm/enum-noprice", lic, `"semantics":"enumerated",`+fns[:len(fns)-1]), wantErr: true,
		},
		// --- invalid: rate rejections (rate is a decimal STRING on the wire) ---
		{
			name: "ENUMERATED / FLAT / malformed rate -> reject", path: "/perm/enum-badrate",
			record: rec("/perm/enum-badrate", lic, `"semantics":"enumerated",`+badRate), wantErr: true,
		},
		{
			name: "ENUMERATED / FREE / non-zero rate -> reject", path: "/perm/enum-free-nonzero",
			record: rec("/perm/enum-free-nonzero", lic, `"semantics":"enumerated",`+freeNonZero), wantErr: true,
		},
		{
			name: "ENUMERATED / numeric rate -> reject at parse", path: "/perm/enum-numrate",
			record: rec("/perm/enum-numrate", lic, `"semantics":"enumerated",`+numericRate), wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A rejection may fire at any of the three ingest legs — parse
			// (e.g. a numeric rate), map (e.g. a malformed rate string), or
			// push (protovalidate) — and each must leave nothing discoverable.
			records, parseErr := ingest.ParseJSONL(strings.NewReader(tc.record))
			var mapErr, pushErr error
			if parseErr == nil {
				var entries []*rampv1.ResourceEntry
				entries, mapErr = ingest.MapRecords(records)
				if mapErr == nil {
					_, pushErr = ingest.PushEntries(h.ctx, h.server.URL, tenant, kid, mustSigningClient(t, kid, priv), entries)
				}
			}
			rejected := parseErr != nil || mapErr != nil || pushErr != nil
			uri := "https://" + domain + tc.path

			if tc.wantErr {
				if !rejected {
					t.Fatalf("want rejection for %s, got accepted", tc.name)
				}
				if got := discoverOfferCount(t, h, uri); got != 0 {
					t.Fatalf("rejected shape %s leaked %d offers (nothing should persist)", tc.name, got)
				}
				return
			}

			if rejected {
				t.Fatalf("want accept for %s, got rejected (parseErr=%v mapErr=%v pushErr=%v)", tc.name, parseErr, mapErr, pushErr)
			}
			terms := discoverTermsAs(t, h, uri, requesterWithExt("perm-agent", "commercial_entity", "DE", "ai-train"))
			if len(terms) == 0 {
				t.Fatalf("accepted shape %s not discoverable", tc.name)
			}
			if tc.wantFn != "" && !termHasFunction(terms[0], tc.wantFn) {
				t.Fatalf("accepted shape %s: machine fields not carried — FUNCTION %q absent from projected term", tc.name, tc.wantFn)
			}
			if tc.wantRate != "" {
				if got := terms[0].GetPricing().GetRate(); got != tc.wantRate {
					t.Fatalf("accepted shape %s: pricing.rate did not survive the round-trip — got %q, want %q", tc.name, got, tc.wantRate)
				}
			}
		})
	}
}

// termHasFunction reports whether term carries a FUNCTION restriction permitting
// tok — the probe that machine fields survived ingestion + projection (the
// flexibility property under REFERENCE_ONLY).
func termHasFunction(term *rampv1.LicenseTerm, tok string) bool {
	for _, r := range term.GetRestrictions() {
		if r.GetKind() != rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION {
			continue
		}
		for _, p := range r.GetPermitted() {
			if p == tok {
				return true
			}
		}
	}
	return false
}

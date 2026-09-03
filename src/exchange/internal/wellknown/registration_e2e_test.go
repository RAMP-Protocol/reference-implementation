// End-to-end tests for the registration half of the Exchange's manifest: the
// account_registration block carrying the schema an agent's registration_data
// must match, and the terms_uri / terms_digest pair naming which terms document
// a registration accepts.
//
// Every assertion about a PUBLISHED value fetches /.well-known/ramp.json over a
// real HTTP round trip and reads the parsed document, which is the same path an
// agent takes. The two refusal tests assert at construction instead, and that
// is the right surface for them: a refused document is never served, so there
// is no request to make.
package wellknown_test

import (
	"encoding/json"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/regschema"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/wellknown"
)

// fetchManifest GETs the served overlay manifest for this role, so every test
// here reads the document the way an agent does.
func fetchManifest(t *testing.T, baseURL string) (*rampwellknown.Manifest, []byte) {
	t.Helper()
	return testutil.FetchManifest(t, baseURL, rampwellknown.RoleExchange)
}

// loadSchema loads raw the way the composition root does, failing the test on a
// schema the Exchange would refuse to boot on.
func loadSchema(t *testing.T, raw string) *regschema.Schema {
	t.Helper()
	s, err := regschema.Load(raw)
	if err != nil {
		t.Fatalf("regschema.Load: %v", err)
	}
	return s
}

// TestRampManifest_PublishesConfiguredRegistrationSchema pins the property the
// whole feature rests on: what an agent reads out of data_schema is what the
// operator configured, member for member. An agent pre-checks its payload
// against this document, so a schema that arrives altered rejects payloads the
// Exchange would have accepted.
func TestRampManifest_PublishesConfiguredRegistrationSchema(t *testing.T) {
	pub, _ := newKeyPair(t)
	cfg := exchangeConfig(pub)
	cfg.RegistrationDataSchema = loadSchema(t, testutil.RegistrationSchemaJSON)
	srv, _ := serveConfig(t, cfg)

	m, _ := fetchManifest(t, srv.URL)
	testutil.AssertServedDataSchema(t, m.GetAccountRegistration().GetDataSchema(), testutil.RegistrationSchemaJSON)
}

// TestRampManifest_PublishesConfiguredTerms pins the terms pair. The digest is
// what makes "which terms did this operator accept" answerable after a later
// revision, so a registration echoes the exact string published here.
func TestRampManifest_PublishesConfiguredTerms(t *testing.T) {
	pub, _ := newKeyPair(t)
	cfg := exchangeConfig(pub)
	cfg.TermsURI, cfg.TermsDigest = testutil.TermsURI, testutil.TermsDigest
	srv, _ := serveConfig(t, cfg)

	m, _ := fetchManifest(t, srv.URL)
	if got := m.GetTermsUri(); got != testutil.TermsURI {
		t.Errorf("terms_uri = %q, want %q", got, testutil.TermsURI)
	}
	if got := m.GetTermsDigest(); got != testutil.TermsDigest {
		t.Errorf("terms_digest = %q, want %q", got, testutil.TermsDigest)
	}
}

// TestRampManifest_TermsDigestSitsBesideTermsURI pins WHERE the digest is
// published, with both values configured so the two possible homes are both
// present in one document. The digest is a top-level member next to terms_uri
// and never a member of account_registration, so an Exchange that inspects no
// registration data and publishes no block can still version its terms.
func TestRampManifest_TermsDigestSitsBesideTermsURI(t *testing.T) {
	pub, _ := newKeyPair(t)
	cfg := exchangeConfig(pub)
	cfg.TermsURI, cfg.TermsDigest = testutil.TermsURI, testutil.TermsDigest
	cfg.RegistrationDataSchema = loadSchema(t, testutil.RegistrationSchemaJSON)
	srv, _ := serveConfig(t, cfg)

	_, raw := fetchManifest(t, srv.URL)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal served manifest: %v", err)
	}
	for _, member := range []string{"terms_uri", "terms_digest"} {
		if _, ok := doc[member]; !ok {
			t.Errorf("%s is not a top-level member of the served manifest", member)
		}
	}
	block, ok := doc["account_registration"].(map[string]any)
	if !ok {
		t.Fatalf("account_registration = %v, want an object", doc["account_registration"])
	}
	if _, ok := block["terms_digest"]; ok {
		t.Error("terms_digest published inside account_registration, want it top-level")
	}
}

// TestRampManifest_OmitsBlockWithoutSchema pins the pass-through default.
// Publishing the block IS the enforcement switch, so an Exchange that inspects
// nothing must publish no block at all — not an empty one, which would read as
// a promise to enforce something.
func TestRampManifest_OmitsBlockWithoutSchema(t *testing.T) {
	pub, _ := newKeyPair(t)
	srv, _ := serveConfig(t, exchangeConfig(pub))

	m, raw := fetchManifest(t, srv.URL)
	if m.GetAccountRegistration() != nil {
		t.Errorf("account_registration = %v, want absent", m.GetAccountRegistration())
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal served manifest: %v", err)
	}
	testutil.AssertRegistrationMembersAbsent(t, doc)
}

// TestRampManifest_RefusesUnusableTermsPair drives the terms refusals at the
// surface that owns them. A digest pins the document at terms_uri, so a digest
// with no URI cannot be checked against anything, and a value that is not
// "method:hexdigest" would be echoed back by a registering agent and could
// never match a real document. Both are refused when the manifest is
// constructed, so the process never serves one carrying them.
func TestRampManifest_RefusesUnusableTermsPair(t *testing.T) {
	for _, tc := range testutil.MalformedTermsDigests {
		t.Run(tc.Name, func(t *testing.T) {
			pub, _ := newKeyPair(t)
			cfg := exchangeConfig(pub)
			cfg.TermsURI, cfg.TermsDigest = tc.URI, tc.Digest
			if _, err := wellknown.New(cfg); err == nil {
				t.Errorf("wellknown.New accepted terms_uri %q with terms_digest %q", tc.URI, tc.Digest)
			}
		})
	}
}

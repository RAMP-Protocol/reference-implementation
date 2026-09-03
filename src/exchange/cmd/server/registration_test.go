package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// servedManifest builds the public mux the way run() does, with the
// registration settings currently in the environment, and returns the
// /.well-known/ramp.json document it serves — parsed, and as the raw bytes the
// wire carried. Reading it back over HTTP is the point: it is the only path an
// agent has to these values.
func servedManifest(t *testing.T) (*rampwellknown.Manifest, map[string]any) {
	t.Helper()
	registration, err := loadRegistrationConfig(discardLogger())
	if err != nil {
		t.Fatalf("loadRegistrationConfig: %v", err)
	}
	srv := httptest.NewServer(buildPublicMux(t, muxDeps{registration: registration}))
	t.Cleanup(srv.Close)

	m, raw := testutil.FetchManifest(t, srv.URL, rampwellknown.RoleExchange)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	return m, doc
}

// TestRegistrationSettingsReachTheManifest drives the wiring an operator
// actually touches: three environment variables in, one served document out.
// The Exchange's manifest is built in code, so a value that never reaches
// wellknown.Config is a value no agent can read.
func TestRegistrationSettingsReachTheManifest(t *testing.T) {
	t.Setenv("EXCHANGE_REGISTRATION_SCHEMA", testutil.RegistrationSchemaJSON)
	t.Setenv("EXCHANGE_TERMS_URI", testutil.TermsURI)
	t.Setenv("EXCHANGE_TERMS_DIGEST", testutil.TermsDigest)

	m, doc := servedManifest(t)

	if got := doc["terms_uri"]; got != testutil.TermsURI {
		t.Errorf("terms_uri = %v, want %q", got, testutil.TermsURI)
	}
	if got := doc["terms_digest"]; got != testutil.TermsDigest {
		t.Errorf("terms_digest = %v, want %q", got, testutil.TermsDigest)
	}
	testutil.AssertServedDataSchema(t, m.GetAccountRegistration().GetDataSchema(), testutil.RegistrationSchemaJSON)
}

// TestUnconfiguredRegistrationLeavesTheManifestUnchanged pins the default. A
// deployment that sets none of the three variables publishes exactly what it
// published before they existed, so upgrading cannot switch enforcement on for
// an operator who never asked for it.
func TestUnconfiguredRegistrationLeavesTheManifestUnchanged(t *testing.T) {
	t.Setenv("EXCHANGE_REGISTRATION_SCHEMA", "")
	t.Setenv("EXCHANGE_TERMS_URI", "")
	t.Setenv("EXCHANGE_TERMS_DIGEST", "")

	_, doc := servedManifest(t)
	testutil.AssertRegistrationMembersAbsent(t, doc)
}

// TestWhitespaceOnlyTermsValuesReadAsUnset pins the trim. An operator whose
// template rendered to a newline has configured nothing, and publishing that
// verbatim would put a terms_uri of " " on the wire for every agent to fetch —
// while the digest half would break the protocol's digest rule and stop the boot
// for a variable the operator believes is empty. It is the same answer the SDK gives
// for a whitespace-only schema, so one blank rule covers all three settings.
func TestWhitespaceOnlyTermsValuesReadAsUnset(t *testing.T) {
	t.Setenv("EXCHANGE_REGISTRATION_SCHEMA", "")
	t.Setenv("EXCHANGE_TERMS_URI", "  \t\n")
	t.Setenv("EXCHANGE_TERMS_DIGEST", " \n ")

	_, doc := servedManifest(t)
	for _, member := range []string{"terms_uri", "terms_digest"} {
		if got, ok := doc[member]; ok {
			t.Errorf("%s = %v in the served manifest, want absent — a whitespace-only value is not a configured one", member, got)
		}
	}
}

// TestTermsDigestRefusalsStopTheBootFromTheEnvironment drives the terms
// refusals the operator documentation promises, through the variables an
// operator actually sets. The rules themselves live in the protocol as
// protovalidate constraints and fire when the manifest message is assembled,
// two layers below this call. Neither refusal has a path that reaches an agent:
// a refused document is never served.
//
// The assertion is on the error TEXT, not merely on there being one. buildMux
// checks several dependencies before it reaches the well-known handler, so a
// call that leaves them nil fails on the recipient interceptor and never
// evaluates the terms pair at all — which would make every case here pass with
// a valid digest, and pass with the terms check deleted. completeMuxDeps fills
// them, and naming both variables is what the error wrapper in registerWellKnown
// exists to provide: the protocol's own message reports a constraint violation
// on a manifest field and names neither variable an operator can edit.
func TestTermsDigestRefusalsStopTheBootFromTheEnvironment(t *testing.T) {
	for _, tc := range testutil.MalformedTermsDigests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Setenv("EXCHANGE_REGISTRATION_SCHEMA", "")
			t.Setenv("EXCHANGE_TERMS_URI", tc.URI)
			t.Setenv("EXCHANGE_TERMS_DIGEST", tc.Digest)

			registration, err := loadRegistrationConfig(discardLogger())
			if err != nil {
				t.Fatalf("loadRegistrationConfig: %v", err)
			}
			_, _, err = buildMux(completeMuxDeps(t, muxDeps{registration: registration}))
			if err == nil {
				t.Fatal("the mux built with a terms pair the protocol refuses")
			}
			for _, envVar := range []string{"EXCHANGE_TERMS_URI", "EXCHANGE_TERMS_DIGEST"} {
				if !strings.Contains(err.Error(), envVar) {
					t.Errorf("buildMux failed with %q, want a failure naming %s", err, envVar)
				}
			}
		})
	}
}

// TestUnusableRegistrationSchemaStopsTheBoot drives the leg the operator
// documentation is really about: the process does not come up. run() is called
// with no database configured, so it would fail on EXCHANGE_DSN if it got that
// far — and the assertion that it fails on the schema instead is what pins the
// schema being resolved BEFORE anything connects. Moving the load back below
// db.Setup fails this test rather than silently costing a connection and a
// migration run per restart of the crash loop.
func TestUnusableRegistrationSchemaStopsTheBoot(t *testing.T) {
	for _, tc := range testutil.UnusableSchemas {
		t.Run(tc.Name, func(t *testing.T) {
			t.Setenv("EXCHANGE_REGISTRATION_SCHEMA", tc.Raw)
			t.Setenv("EXCHANGE_DSN", "")

			err := run(t.Context(), discardLogger())
			if err == nil {
				t.Fatal("run() came up with a schema the Exchange cannot enforce")
			}
			if !strings.Contains(err.Error(), "EXCHANGE_REGISTRATION_SCHEMA") {
				t.Fatalf("run() failed with %q, want a failure naming EXCHANGE_REGISTRATION_SCHEMA", err)
			}
			if !strings.Contains(err.Error(), tc.Verdict) {
				t.Errorf("run() failed with %q, want it to name the verdict %q", err, tc.Verdict)
			}
		})
	}
}

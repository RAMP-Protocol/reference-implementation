package testutil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// trustProxyHeadersEnv mirrors runhttp.TrustProxyHeadersEnv. Spelled here as a
// literal because runhttp's own tests import this package, so importing
// runhttp back would be an import cycle.
const trustProxyHeadersEnv = "RAMP_TRUST_PROXY_HEADERS"

// AssertProxyTrustExactOptIn pins a service's boot wiring of the proxy-trust
// switch to strict opt-in semantics: only the literal "true" or "1" wires
// TrustProxyHeaders. Any other value — including strings a lenient boolean
// parse would read as true, like "disabled" or "yes" — must leave the
// middleware unwired, because on a directly-exposed service an honored
// X-Forwarded-Proto lets the caller pick the scheme its signature verifies
// against. A typo has to fail closed.
//
// build receives the innermost handler and must return the service's wrapped
// public surface, reading RAMP_TRUST_PROXY_HEADERS from the environment the
// way the real composition root does (the Exchange's and Broker's
// buildWrapped). Shared here so both services prove the same contract without
// duplicating the matrix.
func AssertProxyTrustExactOptIn(t *testing.T, build func(inner http.Handler) http.Handler) {
	t.Helper()
	cases := []struct {
		value   string
		trusted bool
	}{
		{"true", true},
		{"1", true},
		{"", false},
		{"false", false},
		{"disabled", false},
		{"yes", false},
	}
	for _, tc := range cases {
		name := tc.value
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(trustProxyHeadersEnv, tc.value)
			var gotScheme string
			h := build(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotScheme = r.URL.Scheme
			}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			h.ServeHTTP(httptest.NewRecorder(), req)

			wantScheme := ""
			if tc.trusted {
				wantScheme = "https"
			}
			if gotScheme != wantScheme {
				t.Errorf("RAMP_TRUST_PROXY_HEADERS=%q: inner handler saw scheme %q, want %q",
					tc.value, gotScheme, wantScheme)
			}
		})
	}
}

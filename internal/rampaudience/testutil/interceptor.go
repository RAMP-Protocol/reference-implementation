// Package testutil builds the recipient interceptor a test surface needs.
//
// It sits beside rampaudience rather than in the repo-wide internal/testutil so
// that a package with no other need for containers does not link them: that
// package brings in testcontainers through its Redis, Vault, TigerBeetle and
// Zitadel fixtures, and a test that only mounts an interceptor should not pay
// for them. Same shape as internal/rampwellknown/testutil, and the same reason.
package testutil

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
)

// MustInterceptor builds the recipient interceptor for a service published as
// domain, failing the test on a domain the protocol would not accept as an
// identity.
//
// Every served surface in production carries one — both services refuse to
// build a mux without it — so a test that assembled a surface without one would
// be exercising a wiring no deployment has. One definition, so the refusal
// message is the same wherever a test hits it.
func MustInterceptor(tb testing.TB, domain string) *rampaudience.Interceptor {
	tb.Helper()
	i, err := rampaudience.NewInterceptor(domain)
	if err != nil {
		tb.Fatalf("recipient interceptor for %q: %v", domain, err)
	}
	return i
}

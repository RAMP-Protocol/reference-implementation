package main

import (
	"net/http"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// TestBuildWrapped_ProxyTrustRequiresExactOptIn proves the Exchange's boot
// wiring only trusts proxy headers on the exact opt-in values; the matrix and
// rationale live in testutil.AssertProxyTrustExactOptIn.
func TestBuildWrapped_ProxyTrustRequiresExactOptIn(t *testing.T) {
	testutil.AssertProxyTrustExactOptIn(t, func(inner http.Handler) http.Handler {
		return buildWrapped(discardLogger(), inner)
	})
}

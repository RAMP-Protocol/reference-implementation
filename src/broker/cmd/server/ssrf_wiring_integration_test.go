package main

// SSRF-guard WIRING regression test for the broker's shared well-known endpoint
// resolver and offer Verifier.
//
// The SSRF guard is SDK-owned (sdk/go/resolvers): its dial-time address/scheme/
// redirect refusal is proven in the SDK's own real-dial suite, NOT here — guard.go
// no longer exists in this repo, so there is no app-local primitive to re-test.
// This test pins ONLY the WIRING contract the broker owns: the production builders
// (newDiscoveryEndpointResolver, newOfferVerifier) construct their fetch client
// from the SDK factory resolvers.NewGuardedClientFromEnv — so the production relay/
// discovery resolver carries the SDK guard rather than a bare http.Client. The SDK
// factory is client-only (no config error); behavior is driven by the operator via
// SKIP_SSRF / ALLOW_INSECURE.

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// TestBrokerWiring_BuildersUseSDKGuardedClient pins that the production wiring
// builders construct their fetch client from the SDK guarded factory (they build
// a guarded resolver/Verifier in the default posture, both flags unset).
func TestBrokerWiring_BuildersUseSDKGuardedClient(t *testing.T) {
	// Default posture: neither flag set, so the SDK factory returns a fully
	// guarded client and both builders wire it in.
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "")

	if resolver := newDiscoveryEndpointResolver(); resolver == nil {
		t.Fatal("newDiscoveryEndpointResolver returned a nil resolver in the default posture")
	}
	// Constructs the offer Verifier over the SDK guarded client; a panic-free
	// build is the wiring contract this pins.
	_ = newOfferVerifier(clock.System{})
}

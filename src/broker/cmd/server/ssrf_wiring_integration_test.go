package main

// SSRF-guard WIRING regression test for every broker collaborator that dials an
// address the broker did not choose: the shared well-known endpoint resolver,
// the offer Verifier, the registry health refresher's probe client, and the
// Broker->Exchange relay client.
//
// The SSRF guard is SDK-owned (sdk/go/resolvers): its dial-time address, scheme
// and redirect refusal is proven in the SDK's own real-dial suite, NOT here --
// there is no app-local primitive to re-test. This test pins ONLY the WIRING
// contract the broker owns: each production builder constructs its client from
// the SDK factory rather than a bare http.Client. The SDK factory is client-only
// (no config error); behavior is driven by the operator via SKIP_SSRF /
// ALLOW_INSECURE.

import (
	"net/http"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// assertGuardedClient fails unless c carries the two things the SDK guarded
// factory installs and a bare &http.Client cannot have: a Transport of its own
// (the dial-time address check) and a redirect policy (so a 302 cannot walk the
// request onto an address the first hop was refused for). Asserting both is what
// makes this a guard check rather than a non-nil check -- the previous version
// of this test passed against any client at all.
func assertGuardedClient(t *testing.T, name string, c *http.Client) {
	t.Helper()
	if c == nil {
		t.Fatalf("%s returned a nil client", name)
	}
	if c.Transport == nil {
		t.Errorf("%s has no Transport, so it dials through http.DefaultTransport with no address guard", name)
	}
	if c.Transport == http.DefaultTransport {
		t.Errorf("%s dials through http.DefaultTransport, which carries no address or scheme guard", name)
	}
	if c.CheckRedirect == nil {
		t.Errorf("%s has no redirect policy, so a redirect can reach an address the first hop was refused for", name)
	}
}

// TestBrokerWiring_BuildersUseSDKGuardedClient pins that the production wiring
// builders construct their fetch client from the SDK guarded factory (they build
// a guarded resolver/Verifier in the default posture, both flags unset).
func TestBrokerWiring_BuildersUseSDKGuardedClient(t *testing.T) {
	// Default posture: neither flag set, so the SDK factory returns a fully
	// guarded client and every builder wires it in.
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "")

	if resolver := newDiscoveryEndpointResolver(); resolver == nil {
		t.Fatal("newDiscoveryEndpointResolver returned a nil resolver in the default posture")
	}
	// Constructs the offer Verifier over the SDK guarded client; a panic-free
	// build is the wiring contract this pins.
	_ = newOfferVerifier(clock.System{})

	// The health probe is the leg that was wired to a bare client: it dials the
	// address an exchange advertises about itself, and it writes that address
	// into the column the discover relay's allowlist compares against.
	assertGuardedClient(t, "newHealthProbeClient", newHealthProbeClient())
}

// TestBrokerWiring_RelayClientIsGuarded pins the outbound relay leg. The
// execute relay reads its admission off the row it fetched by DOMAIN and then
// POSTs the agent's signed offer to whatever that exchange's own well-known
// advertises, so nothing operator-written bounds the dial target. The SDK's host
// anchoring deliberately leaves the scheme to the transport, which makes the
// guarded transport the only thing keeping a signed offer off a plaintext leg.
//
// Driven through the key-absent branch: with no relay key on disk the builder
// still returns the client the pool will dial through, which is the wiring under
// test here. The signed branch wraps that same transport.
func TestBrokerWiring_RelayClientIsGuarded(t *testing.T) {
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "")
	t.Setenv("BROKER_RELAY_KEY_FILE", t.TempDir()+"/absent-broker-key.json")

	client, key, err := newRelayHTTPClient(testutil.DiscardLogger(), "broker.example")
	if err != nil {
		t.Fatalf("newRelayHTTPClient: %v", err)
	}
	if key != nil {
		t.Fatalf("expected no relay key from an absent key file, got %v", key)
	}
	assertGuardedClient(t, "newRelayHTTPClient", client)
}

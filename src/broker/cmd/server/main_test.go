package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport/transporttest"
)

// TestAgentSig1Resolver_OwnKeysNeverResolveInboundSignatures pins the
// verification contract: the Broker's own-key registry exists only to build
// the served WBA directory, and is NOT part of the inbound sig1 chain — its
// keys' private halves never sign an inbound request (the relay key signs
// outbound Broker→Exchange calls). The inbound resolver is the per-agent
// delegate ALONE: a kid it knows resolves, and every other kid — the
// registry's own relay thumbprint included — reports unknown, no matter what
// the registry contains.
func TestAgentSig1Resolver_OwnKeysNeverResolveInboundSignatures(t *testing.T) {
	t.Parallel()
	relayPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	relayThumbprint, err := helpers.Thumbprint(relayPub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keygen: %v", err)
	}

	d := brokerMuxDeps{
		ownKeys: transporttest.MustRegistry(t, relayPub),
		agentResolver: helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
			"agent-kid": agentPub,
		}),
	}

	got, err := d.agentSig1Resolver().Resolve(context.Background(), "agent-kid")
	if err != nil || !got.Equal(agentPub) {
		t.Errorf("Resolve(agent-kid) = %v, %v; want the per-agent resolver's key", got, err)
	}
	// The registry's relay thumbprint must NOT resolve inbound, and an
	// arbitrary kid stays unknown — the registry plays no part either way.
	for _, kid := range []string{relayThumbprint, "unregistered-kid"} {
		if _, err := d.agentSig1Resolver().Resolve(context.Background(), kid); !errors.Is(err, helpers.ErrUnknownKey) {
			t.Errorf("Resolve(%q) error = %v, want helpers.ErrUnknownKey", kid, err)
		}
	}
}

// minimalBrokerMux builds the non-resolve mux shape the route-level tests
// share — a fresh identity signer, an empty own-key registry, the explicit
// never-resolves inbound resolver buildBrokerMux requires (these tests never
// present a signature), and an empty resolveDeps — wrapped in the same
// public-surface stack run() applies (request-id outermost + URL
// normalization), so every route is exercised the way production serves it.
func minimalBrokerMux(t *testing.T) http.Handler {
	t.Helper()
	_, identityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("identity keygen: %v", err)
	}
	signer, err := signing.NewCoSigner("broker.example", "broker-1", identityPriv, nil)
	if err != nil {
		t.Fatalf("cosigner: %v", err)
	}
	mux, _, err := buildBrokerMux(brokerMuxDeps{
		resolveDeps:   resolve.Deps{},
		signer:        signer,
		brokerID:      "broker-1",
		ownKeys:       transporttest.MustRegistry(t),
		agentResolver: transporttest.NeverResolves(),
	})
	if err != nil {
		t.Fatalf("buildBrokerMux: %v", err)
	}
	return transport.WrapPublicSurface(testutil.DiscardLogger(), mux, runhttp.PublicSurfaceOptions{})
}

// TestBrokerMux_RequestIDCoversWellKnownRoutes asserts the root request-id wrap
// applied in run() covers the public well-known + revocation routes — not just
// /broker/v1/resolve — so every route echoes/sets X-Request-ID, matching the
// Exchange's root-level wrap (LT4). Previously only the resolve route was
// wrapped, leaving these two routes without request-id correlation.
func TestBrokerMux_RequestIDCoversWellKnownRoutes(t *testing.T) {
	t.Parallel()
	// The well-known routes are public (not under the BrokerService
	// connectserver gate), so they pass through the wrapped mux and return 200.
	handler := minimalBrokerMux(t)

	for _, path := range []string{rampwellknown.Path, rampwellknown.RevocationPath} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, rec.Code)
		}
		if rec.Header().Get("X-Request-ID") == "" {
			t.Errorf("%s: missing X-Request-ID (route not under root request-id wrap)", path)
		}
	}

	// A caller-supplied id is echoed, proving propagation (not just generation).
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, rampwellknown.Path, http.NoBody)
	req.Header.Set("X-Request-ID", "corr-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-ID"); got != "corr-123" {
		t.Errorf("X-Request-ID = %q, want corr-123 (echoed)", got)
	}
}

// TestBrokerMux_BespokeResolveRouteGone pins the ADR-019 contract
// cleanup: the bespoke POST /broker/v1/resolve route no longer exists on the
// production mux. The ONLY agent surface is the Connect endpoint
// ramp.v1.BrokerService/Resolve (registered in the same buildBrokerMux), so a
// GET *and* a POST to the old path must both return 404 from the mux.
//
// This is a behavioral assertion through the production mux (buildBrokerMux),
// not a structural source scan: the mux is the outermost surface that owns
// routing, so a request that finds no registered pattern returns 404. It drives
// the real server via httptest. On HEAD the route IS registered
// (main.go:222 mux.Handle("POST /broker/v1/resolve", resolve)), so a POST is
// matched (returns 200/non-404) and a GET to a path with only a POST handler
// returns 405 Method Not Allowed — NOT 404. After the route is deleted, both
// verbs fall through to the mux default → 404. FAILS on HEAD, PASSES after
// removal.
func TestBrokerMux_BespokeResolveRouteGone(t *testing.T) {
	t.Parallel()
	handler := minimalBrokerMux(t)

	const bespokePath = "/broker/v1/resolve"
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequestWithContext(context.Background(), method, bespokePath, http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: status = %d, want 404 (bespoke route must be gone; only the Connect endpoint exists)",
				method, bespokePath, rec.Code)
		}
	}
}

// TestBuildBrokerMux_NilAgentResolverIsRefused pins the composition-root
// contract: a missing inbound resolver is a wiring bug reported as an error
// run() can propagate, never a panic and never a mux that would nil-deref on
// the first signed request.
func TestBuildBrokerMux_NilAgentResolverIsRefused(t *testing.T) {
	_, _, err := buildBrokerMux(brokerMuxDeps{})
	if err == nil {
		t.Fatal("buildBrokerMux with nil agentResolver returned nil error; want a refusal")
	}
	if !strings.Contains(err.Error(), "agentResolver is required") {
		t.Fatalf("error %q is not the missing-resolver refusal", err)
	}
}

// bootstrapRegistry must tolerate an unset BROKER_REGISTRY_FILE. It seeds
// nothing in that case — no Exchange is registered until the operator supplies
// a file — and, critically, it must not reach the YAML decoder: a zero-byte
// document decodes to io.EOF, which would abort the boot of every Broker that
// has not configured a registry file yet.
func TestBootstrapRegistry_NoFileSeedsNothingAndDoesNotError(t *testing.T) {
	t.Setenv("BROKER_REGISTRY_FILE", "")

	repoStub := &countingExchangeRepo{}
	if err := bootstrapRegistry(context.Background(), repoStub, testutil.DiscardLogger()); err != nil {
		t.Fatalf("bootstrapRegistry with no file: %v", err)
	}
	if repoStub.upserts != 0 {
		t.Errorf("expected zero seeded exchanges, got %d", repoStub.upserts)
	}
}

// countingExchangeRepo records how many rows bootstrapRegistry tried to seed.
type countingExchangeRepo struct {
	repo.ExchangeRepo
	upserts int
}

func (c *countingExchangeRepo) UpsertFromBootstrap(
	_ context.Context, m repo.Exchange,
) (repo.Exchange, error) {
	c.upserts++
	return m, nil
}

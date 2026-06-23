package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
)

// TestBrokerMux_RequestIDCoversWellKnownRoutes asserts the root request-id wrap
// applied in run() covers the public well-known + invalidation routes — not just
// /broker/v1/resolve — so every route echoes/sets X-Request-ID, matching the
// Exchange's root-level wrap (LT4). Previously only the resolve route was
// wrapped, leaving these two routes without request-id correlation.
func TestBrokerMux_RequestIDCoversWellKnownRoutes(t *testing.T) {
	t.Parallel()
	_, relayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	signer, err := signing.NewCoSigner("broker.example", "broker-1", relayPriv, nil)
	if err != nil {
		t.Fatalf("cosigner: %v", err)
	}
	logger := testutil.DiscardLogger()
	mux := buildBrokerMux(brokerMuxDeps{
		resolveDeps: transport.Deps{},
		signer:      signer,
		brokerID:    "broker-1",
		agentKeys:   transport.NewKeyRegistry(),
	})
	// Mirror run(): request-id outermost, wrapping the httpsig-wrapped mux. The
	// well-known routes are public (brokerSigRequestPredicate), so httpsig passes
	// them through unverified.
	handler := transport.RequestIDMiddleware(logger, wrapWithHTTPSig(mux, transport.NewKeyRegistry(), nil, nil))

	for _, path := range []string{rampwellknown.Path, rampwellknown.InvalidationPath} {
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

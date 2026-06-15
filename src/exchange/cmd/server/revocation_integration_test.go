//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// TestWellKnownAwareResolver_RevokesThroughMiddleware drives the production
// composition end to end: the real wellKnownAwareResolver (revocation Loader +
// started poller + CompositeResolver) wired into the real httpsig.Middleware. A
// request signed by a kid the Broker publishes verifies; once the Broker revokes
// that kid, the poller picks it up within a couple of intervals and the same
// signature is rejected. This is the consumer half of the revocation feature —
// the Broker producer side is covered in src/broker/internal/transport.
func TestWellKnownAwareResolver_RevokesThroughMiddleware(t *testing.T) {
	const kid = "broker-relay.v1"
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey(kid, now.Add(-time.Hour), now.Add(1000*time.Hour))

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	m := testutil.Manifest(rampwellknown.RoleBroker, "broker.e2e.local", key)
	m.InvalidationUrl = testutil.Ptr(origin.InvalidationURL())
	origin.SetManifest(testutil.MarshalManifest(m))
	// Initial snapshot: nothing revoked, oldest possible as_of.
	origin.SetInvalidation(testutil.MarshalInvalidation(time.Unix(1000, 0)))

	t.Setenv("EXCHANGE_BROKER_WELLKNOWN_URL", origin.URL)
	t.Setenv("EXCHANGE_REVOCATION_POLL_INTERVAL", "150ms")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// http.DefaultClient, not the guarded client: the origin is a loopback
	// httptest server the production guard would (correctly) refuse.
	resolver := wellKnownAwareResolver(ctx, httpsig.NewStaticResolver(nil), http.DefaultClient, slog.Default())

	handler := httpsig.Middleware(resolver, httpsig.NewMemoryReplayStore(nil), httpsig.InterceptorOptions{},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// Active, unrevoked kid → the signature verifies (200).
	if status := signedDiscoverStatus(t, srv, kid, priv); status != http.StatusOK {
		t.Fatalf("active kid: status = %d, want 200", status)
	}

	// Revoke the kid with a strictly-newer snapshot; the poller refreshes and the
	// same signed call is rejected within a few poll intervals.
	origin.SetInvalidation(testutil.MarshalInvalidation(time.Unix(2000, 0), kid))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if status := signedDiscoverStatus(t, srv, kid, priv); status == http.StatusUnauthorized {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked kid still verifying after the poll deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// signedDiscoverStatus signs a fresh DiscoverResources call with (kid, priv) and
// returns the HTTP status the httpsig middleware assigns it.
func signedDiscoverStatus(t *testing.T, srv *httptest.Server, kid string, priv ed25519.PrivateKey) int {
	t.Helper()
	const body = `{}`
	target := srv.URL + "/ramp.v1.ExchangeService/DiscoverResources"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Host = req.URL.Host
	created := time.Now().Unix()
	if err := httpsig.SignRequestRAMP(req, []byte(body), kid, priv, created, created+30); err != nil {
		t.Fatalf("sign: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

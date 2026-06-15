//go:build integration

package xclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// writeRelayKeyFile mirrors scripts/gen-broker-relay-key.sh's output shape.
func writeRelayKeyFile(tb testing.TB, dir, kid string, priv ed25519.PrivateKey, pub ed25519.PublicKey) string {
	tb.Helper()
	b64u := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	doc := map[string]string{
		"kid":         kid,
		"kty":         "OKP",
		"crv":         "Ed25519",
		"alg":         "EdDSA",
		"private_key": b64u(priv.Seed()),
		"public_key":  b64u(pub),
	}
	path := filepath.Join(dir, "broker-key.json")
	data, err := json.Marshal(doc)
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		tb.Fatalf("write: %v", err)
	}
	return path
}

// exchangeStub wraps a handler with the same RFC 9421 middleware the real
// Exchange uses. Static resolver seeded with the expected broker-relay pubkey.
func exchangeStub(tb testing.TB, kid string, pub ed25519.PublicKey) *httptest.Server {
	tb.Helper()
	resolver := httpsig.NewStaticResolver(map[string]ed25519.PublicKey{kid: pub})
	replay := httpsig.NewMemoryReplayStore(nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := httpsig.Middleware(resolver, replay, httpsig.InterceptorOptions{}, inner)
	srv := httptest.NewServer(handler)
	tb.Cleanup(srv.Close)
	return srv
}

// TestIntegration_BrokerRelaySignedRoundTrip drives the full happy path:
// LoadRelayKey → NewSigningTransport → HTTP client → Exchange stub guarded
// by the real httpsig middleware.  The Exchange's resolver has the matching
// pubkey, so the call must succeed (200).
func TestIntegration_BrokerRelaySignedRoundTrip(t *testing.T) {
	const kid = "broker.broker-test.v1"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	keyDir := t.TempDir()
	path := writeRelayKeyFile(t, keyDir, kid, priv, pub)

	key, err := xclient.LoadRelayKey(path)
	if err != nil {
		t.Fatalf("LoadRelayKey: %v", err)
	}
	if key.KID != kid {
		t.Fatalf("kid = %q, want %q", key.KID, kid)
	}

	srv := exchangeStub(t, kid, pub)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: xclient.NewSigningTransport(http.DefaultTransport, key, 30*time.Second, nil),
	}
	body := []byte(`{"q":"x"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s, want 200", resp.StatusCode, string(b))
	}
}

// TestIntegration_BrokerRelayRejectedAfterKeySwap covers the adversarial case:
// the transport signs with a rotated priv key not yet published to the
// Exchange's resolver.  The same kid still resolves to the old pub, so the
// ed25519 verify step must fail and the Exchange must return 401.
func TestIntegration_BrokerRelayRejectedAfterKeySwap(t *testing.T) {
	const kid = "broker.broker-test.v1"
	originalPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen original: %v", err)
	}
	// Attacker key — shares kid with original but Exchange never saw the pub.
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen attacker: %v", err)
	}
	_ = attackerPub

	keyDir := t.TempDir()
	path := writeRelayKeyFile(t, keyDir, kid, attackerPriv, attackerPriv.Public().(ed25519.PublicKey))
	key, err := xclient.LoadRelayKey(path)
	if err != nil {
		t.Fatalf("LoadRelayKey: %v", err)
	}

	// Exchange only knows the ORIGINAL pubkey under this kid.
	srv := exchangeStub(t, kid, originalPub)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: xclient.NewSigningTransport(http.DefaultTransport, key, 30*time.Second, nil),
	}
	body := []byte(`{"q":"x"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (key swap should fail verify)", resp.StatusCode)
	}
}

// TestIntegration_BrokerRelayRejectsMalformedKid guards the kid prefix
// contract: relay kids must start with "broker." so audit logs and
// verifier heuristics can disambiguate relay hops from agent callers in
// the unified /.well-known/ramp.json JWKS.
func TestIntegration_BrokerRelayRejectsMalformedKid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	keyDir := t.TempDir()
	path := writeRelayKeyFile(t, keyDir, "agent-demo.v1", priv, pub)
	if _, err := xclient.LoadRelayKey(path); err == nil {
		t.Fatalf("LoadRelayKey accepted non-broker kid; want prefix rejection")
	}
}

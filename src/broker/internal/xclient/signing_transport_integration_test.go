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

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
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

// exchangeStub wraps a handler with an inline RFC 9421 verify gate that mirrors
// the Exchange's signature check. Static resolver seeded with the expected
// broker-relay pubkey; any request whose first signature does not verify against
// that key is rejected 401.
func exchangeStub(tb testing.TB, kid string, pub ed25519.PublicKey) *httptest.Server {
	tb.Helper()
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{kid: pub})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := helpers.VerifyRequestResolved(r.Context(), r, body, resolver, helpers.VerifyOptions{}); err != nil {
			http.Error(w, "httpsig: "+err.Error(), http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(handler)
	tb.Cleanup(srv.Close)
	return srv
}

// mustSigningTransport builds the relay signing RoundTripper for key, failing
// the test on construction error so the http.Client literal stays a one-liner.
func mustSigningTransport(t *testing.T, key *xclient.RelayKey) http.RoundTripper {
	t.Helper()
	rt, err := xclient.NewSigningTransport(http.DefaultTransport, key, "broker.test.local", 30*time.Second, nil)
	if err != nil {
		t.Fatalf("new signing transport: %v", err)
	}
	return rt
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
	// After the WBA split the relay's keyid is the RFC 7638 thumbprint of its
	// public key, derived from the file (the file's kid is ignored).
	wantKeyid, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if key.KeyID != wantKeyid {
		t.Fatalf("keyid = %q, want %q", key.KeyID, wantKeyid)
	}

	srv := exchangeStub(t, key.KeyID, pub)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: mustSigningTransport(t, key),
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
// the transport signs with an attacker key the Exchange never published. After
// the WBA split the keyid IS the key's thumbprint, so a swapped key presents a
// thumbprint the resolver does not know — the Exchange returns 401.
func TestIntegration_BrokerRelayRejectedAfterKeySwap(t *testing.T) {
	originalPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen original: %v", err)
	}
	// Attacker key — the Exchange never saw this pub.
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen attacker: %v", err)
	}
	_ = attackerPub

	keyDir := t.TempDir()
	path := writeRelayKeyFile(t, keyDir, "ignored-kid", attackerPriv, attackerPriv.Public().(ed25519.PublicKey))
	key, err := xclient.LoadRelayKey(path)
	if err != nil {
		t.Fatalf("LoadRelayKey: %v", err)
	}

	// Exchange only knows the ORIGINAL pubkey (by its thumbprint).
	originalTP, err := helpers.Thumbprint(originalPub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	srv := exchangeStub(t, originalTP, originalPub)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: mustSigningTransport(t, key),
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

// TestIntegration_BrokerRelayDerivesKeyidFromKey guards the post-WBA-split
// contract: the relay's RFC 9421 keyid is derived as the RFC 7638 thumbprint of
// its public key, independent of any (now-ignored) kid in the file. The former
// "broker." kid-prefix requirement is gone — role is the DB requester_type
// discriminator, not a kid namespace.
func TestIntegration_BrokerRelayDerivesKeyidFromKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	keyDir := t.TempDir()
	path := writeRelayKeyFile(t, keyDir, "any-legacy-kid", priv, pub)
	key, err := xclient.LoadRelayKey(path)
	if err != nil {
		t.Fatalf("LoadRelayKey rejected a keyless-kid file: %v", err)
	}
	want, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if key.KeyID != want {
		t.Fatalf("keyid = %q, want thumbprint %q", key.KeyID, want)
	}
}

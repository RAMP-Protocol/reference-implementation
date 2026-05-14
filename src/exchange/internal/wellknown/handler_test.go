package wellknown_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/wellknown"
)

func TestServeJWKS_RoundTrip(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	h := wellknown.New(wellknown.Manifest{Exchange: "test"}, pub, "kid-1")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/marketplace/v1/keys", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/jwk-set+json" {
		t.Errorf("Content-Type = %q, want application/jwk-set+json", ct)
	}

	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("keys count = %d, want 1", len(body.Keys))
	}
	key := body.Keys[0]

	if key.Kty != "OKP" {
		t.Errorf("kty = %q, want OKP", key.Kty)
	}
	if key.Crv != "Ed25519" {
		t.Errorf("crv = %q, want Ed25519", key.Crv)
	}
	if key.Alg != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", key.Alg)
	}
	if key.Use != "sig" {
		t.Errorf("use = %q, want sig", key.Use)
	}
	if key.Kid != "kid-1" {
		t.Errorf("kid = %q, want kid-1", key.Kid)
	}

	// Decode X and compare raw bytes to the generated public key.
	got, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		t.Fatalf("decode X: %v", err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Errorf("X length = %d, want %d", len(got), ed25519.PublicKeySize)
	}
	if string(got) != string(pub) {
		t.Error("X does not match the public key passed to New")
	}
}

func TestServeJWKS_KeyRotation(t *testing.T) {
	t.Parallel()
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen A: %v", err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen B: %v", err)
	}

	muxA := http.NewServeMux()
	wellknown.New(wellknown.Manifest{}, pubA, "kid-a").RegisterRoutes(muxA)

	muxB := http.NewServeMux()
	wellknown.New(wellknown.Manifest{}, pubB, "kid-b").RegisterRoutes(muxB)

	xA := jwksX(t, muxA)
	xB := jwksX(t, muxB)

	if xA == xB {
		t.Error("two different keys produced the same X value")
	}
}

func TestServeManifest(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	manifest := wellknown.Manifest{
		Exchange:           "exchange.test",
		Version:            "1.0",
		ExchangeServiceURL: "https://exchange.test/rpc",
		JWKSURL:            "https://exchange.test/marketplace/v1/keys",
		BaseCurrency:       "USD",
	}
	h := wellknown.New(manifest, pub, "kid-1")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ramp-marketplace.json", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var got wellknown.Manifest
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Exchange != manifest.Exchange {
		t.Errorf("exchange = %q, want %q", got.Exchange, manifest.Exchange)
	}
	if got.JWKSURL != manifest.JWKSURL {
		t.Errorf("jwks_url = %q, want %q", got.JWKSURL, manifest.JWKSURL)
	}
	if got.BaseCurrency != manifest.BaseCurrency {
		t.Errorf("base_currency = %q, want %q", got.BaseCurrency, manifest.BaseCurrency)
	}
}

// jwksX fetches /marketplace/v1/keys from mux and returns the base64url X.
func jwksX(t *testing.T, mux *http.ServeMux) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/marketplace/v1/keys", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body struct {
		Keys []struct {
			X string `json:"x"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Keys) == 0 {
		t.Fatal("no keys in response")
	}
	return body.Keys[0].X
}

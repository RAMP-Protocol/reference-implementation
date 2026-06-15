// End-to-end tests for the Exchange's /.well-known/ramp.json surface. Every
// assertion runs against the real http.ServeMux round-trip so content-type
// headers, routing patterns, and JSON marshaling are exercised the way
// production traffic would hit them.
package wellknown_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/wellknown"
)

func httpGet(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // callers close the body
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func closeResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	_, _ = io.Copy(io.Discard, resp.Body)
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close body: %v", err)
	}
}

const offerKid = "exchange-primary"

func newTestServer(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	hops := int32(4)
	h, err := wellknown.New(wellknown.Config{
		Domain:              "exchange.ramp-demo.com",
		Endpoint:            "https://exchange.ramp-demo.com/ramp.v1.ExchangeService",
		CatalogEndpoint:     "https://exchange.ramp-demo.com/ramp.v1.CatalogService",
		BaseCurrency:        "USD",
		SupportedProfiles:   []string{"ramp-news-v1"},
		MaxIntermediaryHops: &hops,
		OfferKeyID:          offerKid,
		OfferKey:            edPub,
		KeyNotBefore:        time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		KeyNotAfter:         time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("wellknown.New: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, edPriv
}

func TestRampManifest_ShapeAndRole(t *testing.T) {
	srv, _ := newTestServer(t)
	resp := httpGet(t, srv.URL+rampwellknown.Path)
	defer closeResponse(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	body, _ := io.ReadAll(resp.Body)
	m, err := rampwellknown.ParseManifest(body, rampwellknown.RoleExchange)
	if err != nil {
		t.Fatalf("served manifest invalid: %v", err)
	}
	if m.GetDomain() != "exchange.ramp-demo.com" {
		t.Errorf("domain = %q", m.GetDomain())
	}
	if m.GetBaseCurrency() != "USD" {
		t.Errorf("base_currency = %q, want USD", m.GetBaseCurrency())
	}
	if m.GetMaxIntermediaryHops() != 4 {
		t.Errorf("max_intermediary_hops = %d, want 4", m.GetMaxIntermediaryHops())
	}
	if _, ok := rampwellknown.KeyByKid(m, offerKid); !ok {
		t.Errorf("offer key %q absent from public_keys", offerKid)
	}
}

func TestRampManifest_KeyVerifiesOfferSignature(t *testing.T) {
	srv, edPriv := newTestServer(t)
	resp := httpGet(t, srv.URL+rampwellknown.Path)
	defer closeResponse(t, resp)
	body, _ := io.ReadAll(resp.Body)
	m, err := rampwellknown.ParseManifest(body, rampwellknown.RoleExchange)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	key, ok := rampwellknown.KeyByKid(m, offerKid)
	if !ok {
		t.Fatalf("missing offer key")
	}
	pub, err := rampwellknown.PublicKey(key)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	msg := []byte("ramp-offer-signature-round-trip")
	if !ed25519.Verify(pub, msg, ed25519.Sign(edPriv, msg)) {
		t.Fatal("published key failed to verify a signature from its private counterpart")
	}
}

func TestRampManifest_LegacyRoutesRemoved(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{
		"/.well-known/jwks.json",
		"/.well-known/cdn-keys.json",
		"/.well-known/ramp-exchange.json",
	} {
		resp := httpGet(t, srv.URL+path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (route should be gone)", path, resp.StatusCode)
		}
		closeResponse(t, resp)
	}
}

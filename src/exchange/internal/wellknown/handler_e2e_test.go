// End-to-end tests for the Exchange's discovery surface. Every assertion runs
// against the real http.ServeMux round-trip so content-type headers, routing
// patterns, and JSON marshaling are exercised the way production traffic would
// hit them. After the WBA split the surface is two documents: a keyless overlay
// manifest at /.well-known/ramp.json and the offer-signing key published in the
// WBA directory at /.well-known/http-message-signatures-directory.
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

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

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

var keyNotBefore = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

func newTestServer(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	hops := int32(4)
	h, err := wellknown.New(wellknown.Config{
		Domain:              "exchange.ramp-demo.com",
		Endpoint:            "https://exchange.ramp-demo.com",
		CatalogEndpoint:     "https://exchange.ramp-demo.com",
		BaseCurrency:        "USD",
		SupportedProfiles:   []string{"ramp-news-v1"},
		MaxIntermediaryHops: &hops,
		OfferKey:            edPub,
		KeyNotBefore:        keyNotBefore,
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

// fetchWBAKey fetches the WBA directory and returns the single currently-valid
// offer-signing key, or (nil, false) when none is published/valid.
func fetchWBAKey(t *testing.T, srv *httptest.Server) (ed25519.PublicKey, bool) {
	t.Helper()
	resp := httpGet(t, srv.URL+rampwellknown.WBAPath)
	defer closeResponse(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("WBA status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/jwk-set+json" {
		t.Fatalf("WBA Content-Type = %q, want application/jwk-set+json", got)
	}
	body, _ := io.ReadAll(resp.Body)
	f, err := rampwellknown.ParseWBA(body)
	if err != nil {
		t.Fatalf("served WBA directory invalid: %v", err)
	}
	pub, err := resolvers.ActiveEd25519Key(f, keyNotBefore.Add(time.Hour))
	return pub, err == nil
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
	// The offer key lives in the WBA directory, never in the overlay manifest.
	if _, ok := fetchWBAKey(t, srv); !ok {
		t.Errorf("offer key absent from WBA directory")
	}
}

func TestRampWBA_KeyVerifiesOfferSignature(t *testing.T) {
	srv, edPriv := newTestServer(t)
	pub, ok := fetchWBAKey(t, srv)
	if !ok {
		t.Fatal("missing offer key in WBA directory")
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

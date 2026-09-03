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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
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

// exchangeTestDomain is the placeholder host every test in this package
// publishes under. RFC 6761 reserves .example, so it can never resolve to a
// real party.
const exchangeTestDomain = "exchange.example"

// exchangeConfig is the production-shaped Config every test in this package
// starts from, on a deterministic clock. A test that pins one field adjusts the
// returned value rather than restating the whole thing, so the shared shape
// moves in one place.
func exchangeConfig(offerKey ed25519.PublicKey) wellknown.Config {
	hops := int32(4)
	return wellknown.Config{
		Domain:              exchangeTestDomain,
		Endpoint:            "https://" + exchangeTestDomain,
		CatalogEndpoint:     "https://" + exchangeTestDomain,
		BaseCurrency:        "USD",
		SupportedProfiles:   []string{"ramp-news-v1"},
		MaxIntermediaryHops: &hops,
		OfferKey:            offerKey,
		Clock:               clock.NewDeterministic(keyNotBefore),
		KeyLifetime:         274 * 24 * time.Hour,
	}
}

// serveConfig mounts cfg's discovery surface on a real http.ServeMux behind an
// httptest server, so every assertion runs over an actual HTTP round trip. The
// handler pair is returned alongside for the one test that drives its
// refresher directly.
func serveConfig(t *testing.T, cfg wellknown.Config) (*httptest.Server, server.Handlers) {
	t.Helper()
	h, err := wellknown.New(cfg)
	if err != nil {
		t.Fatalf("wellknown.New: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, h
}

// newKeyPair returns a fresh Ed25519 offer-signing pair.
func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return pub, priv
}

func newTestServer(t *testing.T) (*httptest.Server, ed25519.PrivateKey) {
	t.Helper()
	edPub, edPriv := newKeyPair(t)
	srv, _ := serveConfig(t, exchangeConfig(edPub))
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
	// The content type is the one property the shared fetch helper does not
	// carry, so it is asserted on its own response before the document itself
	// is read back through that helper.
	resp := httpGet(t, srv.URL+rampwellknown.Path)
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	closeResponse(t, resp)

	m, _ := fetchManifest(t, srv.URL)
	if m.GetDomain() != exchangeTestDomain {
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

// servedOfferWindow fetches the served WBA directory and returns the parsed
// validity window of its single published key.
func servedOfferWindow(t *testing.T, baseURL string) (time.Time, time.Time) {
	t.Helper()
	resp := httpGet(t, baseURL+rampwellknown.WBAPath)
	defer closeResponse(t, resp)
	body, _ := io.ReadAll(resp.Body)
	f, err := rampwellknown.ParseWBA(body)
	if err != nil {
		t.Fatalf("served WBA directory invalid: %v", err)
	}
	if n := len(f.GetKeys()); n != 1 {
		t.Fatalf("served WBA directory has %d keys, want 1", n)
	}
	k := f.GetKeys()[0]
	nb, err := time.Parse(time.RFC3339, k.GetNotBefore())
	if err != nil {
		t.Fatalf("not_before %q: %v", k.GetNotBefore(), err)
	}
	na, err := time.Parse(time.RFC3339, k.GetNotAfter())
	if err != nil {
		t.Fatalf("not_after %q: %v", k.GetNotAfter(), err)
	}
	return nb, na
}

// TestRampWBA_RefresherKeepsWindowFresh is the Exchange's guard against the
// frozen-directory defect: the served WBA document embeds a validity window
// read from the clock at build time, so a process that never rebuilds
// eventually serves only a lapsed window while staying healthy. The test
// builds the directory on a deterministic clock, advances the clock, runs the
// production refresher, and asserts THROUGH THE SERVED ROUTE that the
// published window re-anchors to the advanced clock (start backdated by the
// one-hour clock-skew allowance). If run() stops starting the refresher this
// test still passes — it pins the handler property; the wiring lives in
// cmd/server.
func TestRampWBA_RefresherKeepsWindowFresh(t *testing.T) {
	buildTime := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	clk := clock.NewDeterministic(buildTime)
	edPub, _ := newKeyPair(t)
	const lifetime = 10 * 365 * 24 * time.Hour
	cfg := exchangeConfig(edPub)
	cfg.Clock, cfg.KeyLifetime = clk, lifetime
	srv, h := serveConfig(t, cfg)

	if nb, _ := servedOfferWindow(t, srv.URL); !nb.Equal(buildTime.Add(-time.Hour)) {
		t.Fatalf("initial not_before = %s, want %s (build time minus the clock-skew allowance)", nb, buildTime.Add(-time.Hour))
	}

	advanced := buildTime.Add(5 * 365 * 24 * time.Hour)
	clk.SetNow(advanced)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.RunRefresher(ctx, time.Millisecond, slog.New(slog.DiscardHandler))

	deadline := time.Now().Add(5 * time.Second)
	for {
		if nb, na := servedOfferWindow(t, srv.URL); nb.Equal(advanced.Add(-time.Hour)) {
			if want := advanced.Add(lifetime); !na.Equal(want) {
				t.Fatalf("refreshed not_after = %s, want %s", na, want)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("served window never re-anchored to the advanced clock: the refresher is not rebuilding the document")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

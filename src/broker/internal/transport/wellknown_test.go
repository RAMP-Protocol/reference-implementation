package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	sharedtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport/transporttest"
)

// brokerDiscovery builds a broker well-known handler pair (keyless manifest +
// WBA directory) for keys + revURL on clk (nil → system clock), serves both
// routes over httptest, and returns the server, the co-signing IDENTITY key's
// public half so callers can assert on thumbprints, and the handler pair so
// callers can drive the periodic refresher. The identity signer is freshly
// generated per call; the RELAY key, when a test needs one, goes into keys —
// the registry the served directory publishes alongside the identity key.
func brokerDiscovery(t *testing.T, clk clock.Clock, keys *transport.KeyRegistry, revURL string,
) (*httptest.Server, ed25519.PublicKey, server.Handlers) {
	t.Helper()
	identityPub, identityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("identity keygen: %v", err)
	}
	signer, err := signing.NewCoSigner("broker.example", "broker-1", identityPriv, clk)
	if err != nil {
		t.Fatalf("cosigner: %v", err)
	}
	h, err := transport.NewWellKnown(transport.WellKnownConfig{
		Signer: signer, BrokerID: "broker-1", Keys: keys, RevocationURL: revURL,
	})
	if err != nil {
		t.Fatalf("new well-known: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, identityPub, h
}

// keyWindow extracts one key's parsed validity window from a served WBA
// directory, failing the test on an absent thumbprint or a malformed bound.
func keyWindow(t *testing.T, f *rampv1.WBAFile, tp string) (time.Time, time.Time) {
	t.Helper()
	k, ok := rampwellknown.KeyByThumbprint(f, tp)
	if !ok {
		t.Fatalf("WBA directory missing thumbprint %q", tp)
	}
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

// getBody GETs url and returns the body. The manifest fetches in this file go
// through sharedtestutil.FetchManifest instead, which is where every package
// reading a served manifest goes; this one covers the WBA directory, which has
// no shared equivalent yet.
func getBody(t *testing.T, url string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("close body: %v", cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	return body
}

// TestWellKnownHandler_ServesBrokerDiscovery asserts the Broker serves a
// schema-valid keyless role=ROLE_BROKER overlay manifest AND a WBA directory
// carrying both the co-signing identity key and every own-key-registry key
// (the relay key).
func TestWellKnownHandler_ServesBrokerDiscovery(t *testing.T) {
	t.Parallel()
	relayPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	reg := transporttest.MustRegistry(t, relayPub)

	srv, identityPub, _ := brokerDiscovery(t, nil, reg, "")

	m, _ := sharedtestutil.FetchManifest(t, srv.URL, rampwellknown.RoleBroker)
	if m.GetDomain() != "broker.example" {
		t.Errorf("domain = %q, want broker.example", m.GetDomain())
	}

	f, err := rampwellknown.ParseWBA(getBody(t, srv.URL+rampwellknown.WBAPath))
	if err != nil {
		t.Fatalf("served WBA directory invalid: %v", err)
	}
	for _, tp := range []string{rwtestutil.MustThumbprint(t, identityPub), rwtestutil.MustThumbprint(t, relayPub)} {
		if _, ok := rampwellknown.KeyByThumbprint(f, tp); !ok {
			t.Errorf("WBA directory missing expected thumbprint %q", tp)
		}
	}
	// No revocation URL configured → the field is omitted.
	if got := f.GetRevocationUrl(); got != "" {
		t.Errorf("unexpected revocation_url %q with no URL configured", got)
	}
}

// TestWellKnownHandler_KeysCarryBoundedWindows asserts every key in the served
// WBA directory carries a bounded validity window anchored to the signer clock
// at document build — exactly [now - 1h, now + 90 days) for the identity key
// and the registry key alike. The one-hour backdate is the clock-skew
// allowance: a verifier slightly behind the Broker's clock must accept a
// just-built document. This is the guard against a placeholder window
// (2020→2099 or similar) returning: with no static key file anywhere, the
// published window is the only automatic expiry a verifier gets on a
// rotated-out relay key it still holds in a stale cached directory.
func TestWellKnownHandler_KeysCarryBoundedWindows(t *testing.T) {
	t.Parallel()
	const (
		lifetime = 90 * 24 * time.Hour
		skew     = time.Hour
	)
	buildTime := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	clk := clock.NewDeterministic(buildTime)

	relayPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	reg := transporttest.MustRegistry(t, relayPub)

	srv, identityPub, _ := brokerDiscovery(t, clk, reg, "")
	f, err := rampwellknown.ParseWBA(getBody(t, srv.URL+rampwellknown.WBAPath))
	if err != nil {
		t.Fatalf("served WBA directory invalid: %v", err)
	}

	for name, tp := range map[string]string{
		"identity": rwtestutil.MustThumbprint(t, identityPub),
		"relay":    rwtestutil.MustThumbprint(t, relayPub),
	} {
		nb, na := keyWindow(t, f, tp)
		if !nb.Equal(buildTime.Add(-skew)) || !na.Equal(buildTime.Add(lifetime)) {
			t.Errorf("%s key window = [%s, %s), want [%s, %s)",
				name, nb, na, buildTime.Add(-skew), buildTime.Add(lifetime))
		}
	}
}

// TestWellKnownHandler_RefresherKeepsWindowsFresh is the regression guard for
// the frozen-directory defect: the served WBA document is marshaled at build
// and the windows inside it come from the clock at that moment, so a process
// that never rebuilds eventually serves only lapsed windows while staying
// healthy — every relayed request then fails signature verification until a
// restart. The test builds the directory on a deterministic clock, advances
// the clock most of the way through the 90-day lifetime, runs the production
// refresher, and asserts THROUGH THE SERVED ROUTE that the published window
// re-anchors to the advanced clock. If the refresher stops rebuilding, or a
// rebuild stops re-reading the clock, the poll below times out.
func TestWellKnownHandler_RefresherKeepsWindowsFresh(t *testing.T) {
	t.Parallel()
	buildTime := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	clk := clock.NewDeterministic(buildTime)
	srv, identityPub, h := brokerDiscovery(t, clk, transporttest.MustRegistry(t), "")
	tp := rwtestutil.MustThumbprint(t, identityPub)

	f, err := rampwellknown.ParseWBA(getBody(t, srv.URL+rampwellknown.WBAPath))
	if err != nil {
		t.Fatalf("served WBA directory invalid: %v", err)
	}
	if nb, _ := keyWindow(t, f, tp); !nb.Equal(buildTime.Add(-time.Hour)) {
		t.Fatalf("initial not_before = %s, want %s (build time minus the clock-skew allowance)", nb, buildTime.Add(-time.Hour))
	}

	advanced := buildTime.Add(60 * 24 * time.Hour)
	clk.SetNow(advanced)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.RunRefresher(ctx, time.Millisecond, slog.New(slog.DiscardHandler))

	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := rampwellknown.ParseWBA(getBody(t, srv.URL+rampwellknown.WBAPath))
		if err != nil {
			t.Fatalf("served WBA directory invalid: %v", err)
		}
		if nb, na := keyWindow(t, f, tp); nb.Equal(advanced.Add(-time.Hour)) {
			if want := advanced.Add(90 * 24 * time.Hour); !na.Equal(want) {
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

// TestWellKnownHandler_AdvertisesRevocationURL asserts a configured revocation
// URL is published in the WBA directory so verifiers learn where to poll the
// Broker's KeyRevocationList.
func TestWellKnownHandler_AdvertisesRevocationURL(t *testing.T) {
	t.Parallel()
	const revURL = "https://broker.example/.well-known/ramp-key-revocations.json"
	srv, _, _ := brokerDiscovery(t, nil, transporttest.MustRegistry(t), revURL)
	f, err := rampwellknown.ParseWBA(getBody(t, srv.URL+rampwellknown.WBAPath))
	if err != nil {
		t.Fatalf("served WBA directory invalid: %v", err)
	}
	if got := f.GetRevocationUrl(); got != revURL {
		t.Errorf("revocation_url = %q, want %q", got, revURL)
	}
}

// TestRevocationHandler exercises the file-driven KeyRevocationList route:
// absent/no file → epoch-empty snapshot; present file served verbatim; a
// malformed file → 500 (never an empty snapshot that could un-revoke a key).
func TestRevocationHandler(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "revoked.json")
	if err := os.WriteFile(good, []byte(`{"as_of":"2026-06-04T00:00:00Z","revoked":["k1"]}`), 0o600); err != nil {
		t.Fatalf("write good file: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{not json`), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		wantStatus  int
		wantRevoked []string
	}{
		{"no file configured", "", http.StatusOK, nil},
		{"absent file", filepath.Join(dir, "missing.json"), http.StatusOK, nil},
		{"present file served", good, http.StatusOK, []string{"k1"}},
		{"malformed file rejected", bad, http.StatusInternalServerError, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(transport.NewRevocationHandler(tc.path))
			defer srv.Close()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", resp.StatusCode, tc.wantStatus, body)
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			if err := rampwellknown.ValidateRevocation(body); err != nil {
				t.Fatalf("served list invalid: %v", err)
			}
			var list rampv1.KeyRevocationList
			if err := protojson.Unmarshal(body, &list); err != nil {
				t.Fatalf("decode list: %v", err)
			}
			if !slices.Equal(list.GetRevoked(), tc.wantRevoked) {
				t.Errorf("revoked = %v, want %v", list.GetRevoked(), tc.wantRevoked)
			}
		})
	}
}

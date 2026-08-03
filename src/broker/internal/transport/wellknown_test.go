package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
)

// brokerDiscovery builds a broker well-known handler pair (keyless manifest +
// WBA directory) for keys + revURL, serves both routes over httptest, and
// returns the server plus the relay signer's public key so callers can assert
// on thumbprints. The relay signer is freshly generated per call.
func brokerDiscovery(t *testing.T, keys *transport.KeyRegistry, revURL string) (*httptest.Server, ed25519.PublicKey) {
	t.Helper()
	relayPub, relayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	signer, err := signing.NewCoSigner("broker.example", "broker-1", relayPriv, nil)
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
	return srv, relayPub
}

func getBody(t *testing.T, url string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return body
}

// TestWellKnownHandler_ServesBrokerDiscovery asserts the Broker serves a
// schema-valid keyless role=ROLE_BROKER overlay manifest AND a WBA directory
// carrying both the relay key and every key folded in from the agent registry.
func TestWellKnownHandler_ServesBrokerDiscovery(t *testing.T) {
	t.Parallel()
	reg := transport.NewKeyRegistry()
	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keygen: %v", err)
	}
	reg.PutPublicKey(agentPub)

	srv, relayPub := brokerDiscovery(t, reg, "")

	m, err := rampwellknown.ParseManifest(getBody(t, srv.URL+rampwellknown.Path), rampwellknown.RoleBroker)
	if err != nil {
		t.Fatalf("served broker manifest invalid: %v", err)
	}
	if m.GetDomain() != "broker.example" {
		t.Errorf("domain = %q, want broker.example", m.GetDomain())
	}

	f, err := rampwellknown.ParseWBA(getBody(t, srv.URL+rampwellknown.WBAPath))
	if err != nil {
		t.Fatalf("served WBA directory invalid: %v", err)
	}
	for _, tp := range []string{rwtestutil.MustThumbprint(t, relayPub), rwtestutil.MustThumbprint(t, agentPub)} {
		if _, ok := rampwellknown.KeyByThumbprint(f, tp); !ok {
			t.Errorf("WBA directory missing expected thumbprint %q", tp)
		}
	}
	// No revocation URL configured → the field is omitted.
	if got := f.GetRevocationUrl(); got != "" {
		t.Errorf("unexpected revocation_url %q with no URL configured", got)
	}
}

// TestWellKnownHandler_AdvertisesRevocationURL asserts a configured revocation
// URL is published in the WBA directory so verifiers learn where to poll the
// Broker's KeyRevocationList.
func TestWellKnownHandler_AdvertisesRevocationURL(t *testing.T) {
	t.Parallel()
	const revURL = "https://broker.example/.well-known/ramp-key-revocations.json"
	srv, _ := brokerDiscovery(t, transport.NewKeyRegistry(), revURL)
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

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
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
)

// brokerManifest builds a broker well-known handler for keys + invURL, serves it
// over httptest, and returns the parsed role=ROLE_BROKER manifest. The relay
// signer is freshly generated per call.
func brokerManifest(t *testing.T, keys *transport.KeyRegistry, invURL string) *rampwellknown.Manifest {
	t.Helper()
	_, relayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	signer, err := signing.NewCoSigner("broker.example", "broker-1", relayPriv, nil)
	if err != nil {
		t.Fatalf("cosigner: %v", err)
	}
	h, err := transport.NewWellKnown(transport.WellKnownConfig{
		Signer: signer, BrokerID: "broker-1", Keys: keys, InvalidationURL: invURL,
	})
	if err != nil {
		t.Fatalf("new well-known: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(h.ServeHTTP))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+rampwellknown.Path, http.NoBody)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	m, err := rampwellknown.ParseManifest(body, rampwellknown.RoleBroker)
	if err != nil {
		t.Fatalf("served broker manifest invalid: %v", err)
	}
	return m
}

// TestWellKnownHandler_ServesBrokerManifest asserts the Broker serves a
// schema-valid role=ROLE_BROKER manifest carrying both the relay key and every
// key folded in from the agent registry.
func TestWellKnownHandler_ServesBrokerManifest(t *testing.T) {
	t.Parallel()
	reg := transport.NewKeyRegistry()
	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keygen: %v", err)
	}
	reg.PutPublicKey("agent.demo.v1", agentPub)

	m := brokerManifest(t, reg, "")
	if m.GetDomain() != "broker.example" {
		t.Errorf("domain = %q, want broker.example", m.GetDomain())
	}
	for _, kid := range []string{"broker-1-ed25519", "agent.demo.v1"} {
		if _, ok := rampwellknown.KeyByKid(m, kid); !ok {
			t.Errorf("manifest missing expected kid %q", kid)
		}
	}
	// No invalidation URL configured → the field is omitted.
	if got := m.GetInvalidationUrl(); got != "" {
		t.Errorf("unexpected invalidation_url %q with no URL configured", got)
	}
}

// TestWellKnownHandler_AdvertisesInvalidationURL asserts a configured
// invalidation URL is published in the manifest so verifiers learn where to
// poll the Broker's KeyInvalidationList.
func TestWellKnownHandler_AdvertisesInvalidationURL(t *testing.T) {
	t.Parallel()
	const invURL = "https://broker.example/.well-known/ramp-invalidations.json"
	m := brokerManifest(t, transport.NewKeyRegistry(), invURL)
	if got := m.GetInvalidationUrl(); got != invURL {
		t.Errorf("invalidation_url = %q, want %q", got, invURL)
	}
}

// TestInvalidationHandler exercises the file-driven KeyInvalidationList route:
// absent/no file → epoch-empty snapshot; present file served verbatim; a
// malformed file → 500 (never an empty snapshot that could un-revoke a key).
func TestInvalidationHandler(t *testing.T) {
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
			srv := httptest.NewServer(transport.NewInvalidationHandler(tc.path))
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
			if err := rampwellknown.ValidateInvalidation(body); err != nil {
				t.Fatalf("served list invalid: %v", err)
			}
			var list rampv1.KeyInvalidationList
			if err := protojson.Unmarshal(body, &list); err != nil {
				t.Fatalf("decode list: %v", err)
			}
			if !slices.Equal(list.GetRevoked(), tc.wantRevoked) {
				t.Errorf("revoked = %v, want %v", list.GetRevoked(), tc.wantRevoked)
			}
		})
	}
}

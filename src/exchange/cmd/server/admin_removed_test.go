package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// noopRegistry is a trivial agentreg.Registry that refuses everything. It
// satisfies the interface so buildMux can wire the agents-register route; we
// never exercise its methods in the 404 regression test.
type noopRegistry struct{}

func (noopRegistry) LookupPublicKey(_ context.Context, _ string) (ed25519.PublicKey, error) {
	return nil, errors.New("unused in admin-removed regression test")
}

func (noopRegistry) RegisterFromDirectory(_ context.Context, _, _ string) error {
	return errors.New("unused in admin-removed regression test")
}

func (noopRegistry) RefreshDirectoryKey(_ context.Context, _ string) error {
	return errors.New("unused in admin-removed regression test")
}

// ─────────────────────────────────────────────────────────────────────────
// LEGACY — NOT COMING BACK. PERIOD.
//
// The /admin/* surface existed only as a test-time shortcut around the
// catalog-push signing + contributor-authorization gates. It had zero
// auth, zero tenant isolation, and would have rotted into a production
// footgun the moment it stayed compiled in. We removed it and we are
// NOT restoring it, under any "just for tests" pretext. If you are
// looking here because a harness needs to seed catalog rows, use the
// `ramp.v1.CatalogService/PushResources` RPC — that is the only way
// catalog data enters the live trie, in tests and in production alike.
//
// This file's sole remaining job: assert the admin routes stay 404, so the
// surface cannot reappear by accident. This includes BOTH the legacy
// /admin/* REST shortcuts AND the Connect procedure paths for the
// ramp.admin.v1.AdminService (SetTenantFeeRate, SetReportingPolicy).
// Adding any admin handler to buildMux will cause one of these assertions
// to fail.
// ─────────────────────────────────────────────────────────────────────────
//
// TestAdminRoutesReturn404 is the cheap, DB-free compile-time guard. The
// integration-tagged companion — which also asserts the public routes
// still serve — lives at
// src/exchange/internal/transport/admin_removed_e2e_test.go.
func TestAdminRoutesReturn404(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	offerSigner, err := signing.NewEd25519Signer(pub, priv)
	if err != nil {
		t.Fatalf("offer signer: %v", err)
	}
	mux, _, err := buildMux(muxDeps{
		pool:          nil, // healthzHandler tolerates nil
		exchange:      nil, // Connect-Go handlers register against nil; never invoked here
		catalog:       nil,
		agentRegistry: noopRegistry{},
		offerSigner:   offerSigner,
	})
	if err != nil {
		t.Fatalf("build mux: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cases := []struct {
		method string
		path   string
		body   io.Reader // nil uses empty body
	}{
		{http.MethodPost, "/admin/seed", nil},
		{http.MethodPost, "/admin/catalog/reload", nil},
		{http.MethodGet, "/admin/catalog", nil},
		{http.MethodGet, "/admin/keys/rsa-public.pem", nil},
		// Connect procedure paths for the admin surface — must not appear on
		// the public mux. These are unsigned, unauthenticated setters that
		// change money and policy; only the separate internal listener (with
		// IP-allowlist) should serve them.
		{http.MethodPost, "/ramp.admin.v1.AdminService/SetTenantFeeRate", strings.NewReader(`{"ver":"1.0","rate":{"tenant_id":"t_test","fee_rate_bps":100}}`)},
		{http.MethodPost, "/ramp.admin.v1.AdminService/SetReportingPolicy", strings.NewReader(`{"ver":"1.0","policy":{"tenant_id":"t_test"}}`)},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var body io.Reader
			if tc.body != nil {
				body = tc.body
			} else {
				body = strings.NewReader("")
			}
			req, err := http.NewRequestWithContext(
				context.Background(), tc.method, srv.URL+tc.path, body,
			)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			// Connect procedure paths need JSON content-type for the server to
			// even attempt route matching; the assertion is 404 (route absent),
			// not 400/415 (route exists but content wrong).
			if tc.method == http.MethodPost && tc.body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("want 404, got %d", resp.StatusCode)
			}
		})
	}
}

// TestHealthzStillRegistered ensures the refactor from inline wiring to
// buildMux didn't silently drop a route that the rest of the surface still
// needs.
func TestHealthzStillRegistered(t *testing.T) {
	mux, _, err := buildMux(muxDeps{
		pool:          nil,
		agentRegistry: noopRegistry{},
		offerSigner:   mustSigner(t),
	})
	if err != nil {
		t.Fatalf("build mux: %v", err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/healthz", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", resp.StatusCode)
	}
}

func mustSigner(t *testing.T) *signing.Ed25519Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	s, err := signing.NewEd25519Signer(pub, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

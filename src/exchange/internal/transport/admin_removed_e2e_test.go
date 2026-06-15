//go:build integration

package transport_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// ─────────────────────────────────────────────────────────────────────────
// LEGACY — NOT COMING BACK. PERIOD.
//
// The /admin/* surface was a test-time shortcut around contributor-auth
// and httpsig. It is gone. It stays gone. The production-equivalent
// path for seeding catalog data is `ramp.v1.CatalogService/PushResources`,
// which every e2e harness is expected to exercise end-to-end.
//
// Do NOT restore an admin endpoint "just for tests." If a harness is
// struggling to seed state, the fix is to sign a real PushResources RPC,
// not to weaken the authorization model. This file is a tripwire, not
// a design affordance.
// ─────────────────────────────────────────────────────────────────────────
//
// TestAdminRoutesReturn404 boots the full production HTTP surface via
// startExchangeServer (which mirrors buildMux in cmd/server/main.go) and
// asserts every documented admin URL returns 404. A cheap compile-time
// companion lives at src/exchange/cmd/server/admin_removed_test.go.
func TestAdminRoutesReturn404(t *testing.T) {
	h := newTestHarness(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   io.Reader
	}{
		{
			name:   "POST /admin/seed (with plausible payload)",
			method: http.MethodPost,
			path:   "/admin/seed",
			// A request body shaped like the old seed payload. Content is
			// irrelevant; only that the route would have accepted one.
			body: strings.NewReader(`{"tenants":[{"tenant_id":"t_demo"}],"catalog":[]}`),
		},
		{
			name:   "POST /admin/catalog/reload",
			method: http.MethodPost,
			path:   "/admin/catalog/reload",
			body:   http.NoBody,
		},
		{
			name:   "GET /admin/catalog",
			method: http.MethodGet,
			path:   "/admin/catalog",
			body:   nil,
		},
		{
			name:   "GET /admin/keys/rsa-public.pem",
			method: http.MethodGet,
			path:   "/admin/keys/rsa-public.pem",
			body:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(h.ctx, tc.method, h.server.URL+tc.path, tc.body)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			if tc.body != nil && tc.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := h.server.Client().Do(req)
			if err != nil {
				t.Fatalf("http do: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s %s: status = %d, want 404", tc.method, tc.path, resp.StatusCode)
			}
		})
	}
}

// TestPublicSurfacesStillServe is the positive companion to the 404 regression
// guard above: it proves that the admin removal did not accidentally sever any
// of the public routes the Exchange is expected to expose. All assertions run
// against the same server instance used by TestAdminRoutesReturn404's cousin
// harness, so "admin removed AND public served" is a single-boot property.
func TestPublicSurfacesStillServe(t *testing.T) {
	h := newTestHarness(t)

	t.Run("GET /.well-known/ramp.json serves the unified manifest", func(t *testing.T) {
		resp := getJSON(t, h, rampwellknown.Path, "application/json")
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read ramp.json: %v", err)
		}
		if _, err := rampwellknown.ParseManifest(body, rampwellknown.RoleExchange); err != nil {
			t.Fatalf("ramp.json invalid: %v", err)
		}
	})

	t.Run("legacy well-known routes are gone", func(t *testing.T) {
		for _, path := range []string{
			"/.well-known/jwks.json",
			"/.well-known/cdn-keys.json",
			"/.well-known/ramp-exchange.json",
		} {
			req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, h.server.URL+path, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := h.server.Client().Do(req)
			if err != nil {
				t.Fatalf("http do: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404 (route should be gone)", path, resp.StatusCode)
			}
		}
	})

	t.Run("POST /exchange/v1/agents/register is registered (not 404)", func(t *testing.T) {
		// A malformed body produces 400 from the public handler; 404 would
		// mean the route is missing. We tolerate any non-2xx non-404 status
		// here because the goal is "route exists", not "happy path works" —
		// the latter is covered by TestAgentsRegister_HappyPathAndSignatureVerifies.
		req, err := http.NewRequestWithContext(h.ctx, http.MethodPost,
			h.server.URL+"/exchange/v1/agents/register",
			strings.NewReader("{not-json"))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := h.server.Client().Do(req)
		if err != nil {
			t.Fatalf("http do: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Fatalf("agents/register missing (404) — route was not wired")
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("agents/register: status = %d, want 400 for malformed JSON", resp.StatusCode)
		}
	})
}

func getJSON(t *testing.T, h *testHarness, path, wantContentType string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, h.server.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("http do %s: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("%s: status = %d, want 200", path, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != wantContentType {
		_ = resp.Body.Close()
		t.Fatalf("%s: Content-Type = %q, want %q", path, got, wantContentType)
	}
	return resp
}

func decodeJSONBody(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(dst); err != nil {
		t.Fatalf("decode body %q: %v", string(raw), err)
	}
}

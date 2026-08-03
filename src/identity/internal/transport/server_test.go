package transport

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// These are pure unit tests: no backends, no build tag, so host dispatch and the
// error-status mapping — the transport's whole job — run under make test-fast.

func TestParseHost(t *testing.T) {
	t.Parallel()
	const base = "rampmcp.org"
	cases := []struct {
		name, host string
		wantSub    string
		wantOK     bool
	}{
		{"single label", "agent-123.rampmcp.org", "agent-123.rampmcp.org", true},
		{"strips port", "agent-123.rampmcp.org:8083", "agent-123.rampmcp.org", true},
		{"lowercases", "AGENT-123.RAMPMCP.ORG", "agent-123.rampmcp.org", true},
		{"apex is not a child", "rampmcp.org", "", false},
		{"multi-label child", "a.b.rampmcp.org", "", false},
		{"foreign domain", "evil.example.com", "", false},
		{"empty label", ".rampmcp.org", "", false},
		// A single but malformed label passes host-shape parsing; the grammar reject
		// happens downstream in the publisher, so it 404s without a backend call.
		{"malformed label passes shape", "bad_label.rampmcp.org", "bad_label.rampmcp.org", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotSub, gotOK := parseHost(tc.host, base)
			if gotOK != tc.wantOK || gotSub != tc.wantSub {
				t.Fatalf("parseHost(%q) = (%q, %v), want (%q, %v)", tc.host, gotSub, gotOK, tc.wantSub, tc.wantOK)
			}
		})
	}
}

// stubDocs is a DocumentService returning canned results, for the status mapping.
type stubDocs struct {
	body []byte
	err  error
}

func (s stubDocs) Directory(_ context.Context, _ string) ([]byte, error)  { return s.body, s.err }
func (s stubDocs) Card(_ context.Context, _ string) ([]byte, error)       { return s.body, s.err }
func (s stubDocs) Revocation(_ context.Context, _ string) ([]byte, error) { return s.body, s.err }

func TestServe_StatusMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		svc        stubDocs
		wantStatus int
	}{
		{"ok", stubDocs{body: []byte(`{"keys":[]}`)}, http.StatusOK},
		{"absent -> 404", stubDocs{err: publisher.ErrAbsent}, http.StatusNotFound},
		{"unavailable -> 503", stubDocs{err: publisher.ErrUnavailable}, http.StatusServiceUnavailable},
		{"other -> 500", stubDocs{err: context.DeadlineExceeded}, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := NewHandler("rampmcp.org", tc.svc, 300*time.Second)
			mux := http.NewServeMux()
			h.RegisterRoutes(mux)
			srv := httptest.NewServer(mux)
			defer srv.Close()

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+rampwellknown.WBAPath, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Host = "agent-123.rampmcp.org"
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK && resp.Header.Get("Cache-Control") == "" {
				t.Error("Cache-Control missing on a 200")
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	h := NewHandler("rampmcp.org", stubDocs{body: []byte("x")}, 300*time.Second)
	cases := []struct {
		name       string
		health     func(context.Context) error
		wantStatus int
	}{
		{"healthy", func(context.Context) error { return nil }, http.StatusOK},
		{"nil health check", nil, http.StatusOK},
		{"database down", func(context.Context) error { return errors.New("db unreachable") }, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(NewServer(discardLogger(), h, tc.health))
			defer srv.Close()
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/healthz", nil)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("healthz: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("healthz status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

func TestServe_NonSubdomainHost404(t *testing.T) {
	t.Parallel()
	h := NewHandler("rampmcp.org", stubDocs{body: []byte("x")}, 300*time.Second)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+rampwellknown.WBAPath, nil)
	req.Host = "evil.example.com"
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (foreign host never reaches the service)", resp.StatusCode)
	}
}

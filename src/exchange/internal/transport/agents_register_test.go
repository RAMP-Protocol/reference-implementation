package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/time/rate"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// safeBuffer is a mutex-guarded bytes.Buffer so the httptest server goroutine's
// log writes and the test goroutine's reads share a lock the race detector sees.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// stubRegistry is a minimal agentreg.Registry. Only RegisterFromManifest is
// exercised (it returns registerErr); the rate-limit case never reaches it.
type stubRegistry struct{ registerErr error }

func (stubRegistry) LookupPublicKey(context.Context, string) (ed25519.PublicKey, error) {
	panic("stubRegistry.LookupPublicKey is not used by this test")
}

func (s stubRegistry) RegisterFromManifest(context.Context, string, string) error {
	return s.registerErr
}

// TestAgentsRegister_LogsCarryRequestID proves every agents.register log
// site emits through reqctx.FromContext, so the request_id the RequestIDMiddleware
// echoed is correlated on the log line rather than silently dropped. Each branch
// (rate-limited, register-failed, register-ok) hits a distinct log site.
func TestAgentsRegister_LogsCarryRequestID(t *testing.T) {
	t.Parallel()

	const reqID = "corr-reg-1"
	body, err := json.Marshal(map[string]string{
		"agent_id":     "agent.example",
		"manifest_url": "https://agent.example/.well-known/ramp.json",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	denyLimiter := transport.AgentsRegisterOptions{
		LimiterFactory: func() *rate.Limiter { return rate.NewLimiter(0, 0) },
	}
	cases := []struct {
		name       string
		opts       transport.AgentsRegisterOptions
		registry   agentreg.Registry
		wantStatus int
		wantMsg    string
	}{
		{"rate limited", denyLimiter, stubRegistry{}, http.StatusTooManyRequests, "agents.register rate-limited"},
		{
			"register failed",
			transport.AgentsRegisterOptions{},
			stubRegistry{registerErr: agentreg.ErrMalformedManifest},
			http.StatusBadRequest, "agents.register failed",
		},
		{"register ok", transport.AgentsRegisterOptions{}, stubRegistry{}, http.StatusOK, "agents.register ok"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf := &safeBuffer{}
			logger := slog.New(slog.NewJSONHandler(buf, nil))
			h := transport.NewAgentsRegisterHandler(tc.registry, tc.opts)
			mux := http.NewServeMux()
			h.RegisterRoutes(mux)
			srv := httptest.NewServer(transport.RequestIDMiddleware(logger, mux))
			defer srv.Close()

			req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodPost,
				srv.URL+"/exchange/v1/agents/register", bytes.NewReader(body))
			if reqErr != nil {
				t.Fatalf("new request: %v", reqErr)
			}
			req.Header.Set("X-Request-ID", reqID)
			resp, doErr := srv.Client().Do(req)
			if doErr != nil {
				t.Fatalf("do: %v", doErr)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			logged := buf.String()
			if !strings.Contains(logged, tc.wantMsg) {
				t.Fatalf("missing log %q; got: %s", tc.wantMsg, logged)
			}
			if want := `"request_id":"` + reqID + `"`; !strings.Contains(logged, want) {
				t.Fatalf("log line for %q lacks %s; got: %s", tc.wantMsg, want, logged)
			}
		})
	}
}

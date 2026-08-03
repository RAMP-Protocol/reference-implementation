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

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid/agentidtest"
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

// registerArgs records what the handler passed down to the registry, so a test
// can assert on the value the row will be keyed on rather than only on the status
// code the caller sees.
type registerArgs struct{ agentID, discoveryURL string }

// stubRegistry is a minimal agentreg.Registry. Only RegisterFromDirectory is
// exercised (it returns registerErr, and records its arguments when seen is
// non-nil); the rate-limit case never reaches it.
type stubRegistry struct {
	registerErr error
	seen        *registerArgs
}

func (stubRegistry) LookupPublicKey(context.Context, string) (ed25519.PublicKey, error) {
	panic("stubRegistry.LookupPublicKey is not used by this test")
}

func (s stubRegistry) RegisterFromDirectory(_ context.Context, agentID, discoveryURL string) error {
	if s.seen != nil {
		*s.seen = registerArgs{agentID: agentID, discoveryURL: discoveryURL}
	}
	return s.registerErr
}

func (stubRegistry) RefreshDirectoryKey(context.Context, string) error {
	panic("stubRegistry.RefreshDirectoryKey is not used by this test")
}

// TestAgentsRegister_LogsCarryRequestID proves every agents.register log
// site emits through reqctx.FromContext, so the request_id the RequestIDMiddleware
// echoed is correlated on the log line rather than silently dropped. Each branch
// (rate-limited, register-failed, register-ok) hits a distinct log site.
func TestAgentsRegister_LogsCarryRequestID(t *testing.T) {
	t.Parallel()

	const reqID = "corr-reg-1"
	body := map[string]string{
		"agent_id":      "agent.example",
		"discovery_url": "https://agent.example/.well-known/ramp.json",
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
			got := runRegisterCall(t, registerCall{
				registry: tc.registry, opts: tc.opts, body: body, requestID: reqID,
			})
			if got.status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got.status, tc.wantStatus)
			}
			if !strings.Contains(got.logged, tc.wantMsg) {
				t.Fatalf("missing log %q; got: %s", tc.wantMsg, got.logged)
			}
			if want := `"request_id":"` + reqID + `"`; !strings.Contains(got.logged, want) {
				t.Fatalf("log line for %q lacks %s; got: %s", tc.wantMsg, want, got.logged)
			}
		})
	}
}

// registerCall describes one agents/register request. The zero value is the plain
// case: no middleware, no request id, body decoded as JSON.
//
// requestID is what splits the two shapes this suite needs. Set, the server is
// wrapped in RequestIDMiddleware and the header is sent, which is the only way the
// log-correlation cases can observe what they assert. Unset, neither happens.
// Before this was a parameter the suite had two ways to start this server, and
// they had already drifted: every case going through the helper exercised the
// handler WITHOUT the middleware that production always installs.
type registerCall struct {
	registry  agentreg.Registry
	opts      transport.AgentsRegisterOptions
	body      map[string]string
	requestID string
}

// registerResult carries everything a case might assert on. Cases read the fields
// they care about; logged is empty unless registerCall.requestID was set, since
// nothing captures logs otherwise.
type registerResult struct {
	status int
	body   map[string]string
	logged string
}

// runRegisterCall runs one agents/register request against a handler wired with
// call.registry and returns the status, the decoded JSON body, and any log output.
func runRegisterCall(t *testing.T, call registerCall) registerResult {
	t.Helper()
	raw, err := json.Marshal(call.body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	h := transport.NewAgentsRegisterHandler(call.registry, call.opts)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	var handler http.Handler = mux
	buf := &safeBuffer{}
	if call.requestID != "" {
		handler = transport.RequestIDMiddleware(slog.New(slog.NewJSONHandler(buf, nil)), mux)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/exchange/v1/agents/register", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if call.requestID != "" {
		req.Header.Set("X-Request-ID", call.requestID)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	decoded := map[string]string{}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return registerResult{status: resp.StatusCode, body: decoded, logged: buf.String()}
}

// postRegisterStubbed is the plain shape: no middleware, no request id.
func postRegisterStubbed(t *testing.T, registry agentreg.Registry, body map[string]string) (int, map[string]string) {
	t.Helper()
	r := runRegisterCall(t, registerCall{registry: registry, body: body})
	return r.status, r.body
}

// TestAgentsRegister_CanonicalizesAgentIDOnBothSides pins why the handler
// canonicalizes at the edge rather than leaving it to the registry.
//
// Both sides matter and neither was asserted. Downward, the value handed to
// RegisterFromDirectory is what the agents row is keyed on. Upward, the handler
// ECHOES agent_id back as the registered identity and logs it — and that echo is
// the reason the canonicalization sits in the handler at all: left raw, a caller
// that posted "https://a.example" was told it had registered "https://a.example"
// while the table held "a.example", an answer naming a row that does not exist
// and an operator search that finds nothing.
func TestAgentsRegister_CanonicalizesAgentIDOnBothSides(t *testing.T) {
	t.Parallel()

	var seen registerArgs
	status, body := postRegisterStubbed(t, stubRegistry{seen: &seen}, map[string]string{
		// Every folding axis at once, plus surrounding whitespace the handler trims.
		"agent_id":      "  https://Agent.Example:0443  ",
		"discovery_url": "https://Agent.Example",
	})

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %v)", status, body)
	}
	if seen.agentID != "agent.example" {
		t.Errorf("registry received agent_id %q; want %q — this is the string the row is keyed on",
			seen.agentID, "agent.example")
	}
	if body["agent_id"] != "agent.example" {
		t.Errorf("response echoed agent_id %q; want %q — an echo of the raw spelling names a "+
			"row that does not exist", body["agent_id"], "agent.example")
	}
}

// TestAgentsRegister_RejectsAgentIDNamingNoHost drives the 400 branch the
// canonicalization added, which nothing else reached. A value that names no host
// must not become a fetch target, so it is refused before the registry is
// consulted at all — asserted by the registry never being called.
func TestAgentsRegister_RejectsAgentIDNamingNoHost(t *testing.T) {
	t.Parallel()

	for _, tc := range agentidtest.NonHostValues() {
		bad := tc.Value
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			var seen registerArgs
			status, body := postRegisterStubbed(t, stubRegistry{seen: &seen}, map[string]string{
				"agent_id": bad, "discovery_url": bad,
			})
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %v)", status, body)
			}
			// Exact, not a prefix: the point is that this endpoint answers one
			// fault class in one curated shape. A prefix check passed equally on
			// the raw wrapped error this used to return, so it could not see the
			// divergence from classifyRegisterError's arm for the same class.
			if body["error"] != "agent_id does not name a host" {
				t.Errorf("error = %q; want the curated %q",
					body["error"], "agent_id does not name a host")
			}
			if seen.agentID != "" {
				t.Errorf("registry was called with %q; an unusable agent_id must not reach a fetch",
					seen.agentID)
			}
		})
	}
}

// TestAgentsRegister_NotAHostIsNotReportedAsAMalformedManifest pins the
// diagnostic split. discovery_url is not canonicalized at the edge — only its
// anchoring to agent_id is decided, inside the registry — so a discovery_url that
// names no host surfaces here as agentreg.ErrNotAHost. It used to share
// ErrMalformedManifest's arm and answer "manifest is malformed" on an
// unauthenticated public endpoint, sending the caller to inspect a document the
// Exchange never retrieved. The status is unchanged; only the diagnosis is.
func TestAgentsRegister_NotAHostIsNotReportedAsAMalformedManifest(t *testing.T) {
	t.Parallel()

	status, body := postRegisterStubbed(t, stubRegistry{registerErr: agentreg.ErrNotAHost}, map[string]string{
		"agent_id": "agent.example", "discovery_url": "not a host",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if strings.Contains(body["error"], "manifest") {
		t.Errorf("error %q blames a manifest; none was fetched", body["error"])
	}
	if !strings.Contains(body["error"], "does not name a host") {
		t.Errorf("error %q does not state the actual fault", body["error"])
	}
}

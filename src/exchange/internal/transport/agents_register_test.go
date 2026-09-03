package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/time/rate"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid/agentidtest"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
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

// Reset drops what has been captured so far, so one test can assert on the
// lines a second request produced without the first request's still in view.
func (s *safeBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
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
			stubRegistry{registerErr: agentreg.ErrMalformedDirectory},
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

// TestAgentsRegister_NoErrorBlamesTheCommercialOverlay covers every arm of the
// register endpoint's diagnosis, not just the one that was fixed first.
//
// Registration reads exactly one remote document: the caller's Web Bot Auth key
// directory. It never fetches the caller's ramp.json, and the overlay carries no
// key material, so any message naming a manifest describes a repair that cannot
// clear the refusal — an operator publishing keys in ramp.json would still be
// rejected. Each arm below is driven through the real handler; a message that
// reintroduces the word fails here.
//
// The single-case version of this assertion (ErrNotAHost, below) was written when
// only that arm had been corrected. Covering the arms one at a time is how the
// wrong vocabulary survived in the other three, so this drives them together.
func TestAgentsRegister_NoErrorBlamesTheCommercialOverlay(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		err     error
		wantSub string
	}{
		{"not a host", agentreg.ErrNotAHost, "does not name a host"},
		{"host mismatch", agentreg.ErrAgentIDMismatch, "does not match agent_id"},
		{"absent directory", rampwellknown.ErrNoDocument, "no key directory"},
		{"malformed directory", agentreg.ErrMalformedDirectory, "key directory"},
		{"no valid key", agentreg.ErrNoValidKey, "key directory"},
		{"upstream fetch failure", errors.New("dial tcp: connection refused"), "key directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, body := postRegisterStubbed(t, stubRegistry{registerErr: tc.err}, map[string]string{
				"agent_id": "agent.example", "discovery_url": "https://agent.example",
			})
			got := body["error"]
			for _, banned := range []string{"manifest", "ramp.json"} {
				if strings.Contains(got, banned) {
					t.Errorf("error %q names %q; registration reads the key directory, not that document", got, banned)
				}
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("error %q does not state the actual fault (want %q)", got, tc.wantSub)
			}
		})
	}
}

// TestAgentsRegister_StatusFollowsTheSharedCallerFaultSplit pins WHICH answer
// each fault gets, and pins it to the one definition the whole Exchange uses.
//
// Three paths reach the same registry: this endpoint, service.mapLazyRegisterError,
// and the catalog self-signup handler. The other two ask agentreg.IsCallerFault
// whether a failure is permanent. This endpoint used to decide by hand, and it
// disagreed on one sentinel. An agent that serves no key directory got 502
// "failed to fetch the agent's key directory" here, which tells the caller to
// retry, and 401 on the other two, which tells it the identity is not
// registrable. Retrying could never clear it: the origin answered, and it will
// answer 404 again until the caller publishes the document.
//
// wantStatus is written out rather than computed, so the case below is a real
// expectation and not a restatement of the code. The second assertion then ties
// it to IsCallerFault, so the two cannot drift apart again in either direction:
// an endpoint that stops reading the shared split fails the first check, and a
// sentinel that changes sides without this table changing fails the second.
func TestAgentsRegister_StatusFollowsTheSharedCallerFaultSplit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"not a host", agentreg.ErrNotAHost, http.StatusBadRequest},
		{"host mismatch", agentreg.ErrAgentIDMismatch, http.StatusBadRequest},
		{"absent directory", rampwellknown.ErrNoDocument, http.StatusBadRequest},
		{"malformed directory", agentreg.ErrMalformedDirectory, http.StatusBadRequest},
		{"no valid key", agentreg.ErrNoValidKey, http.StatusBadRequest},
		// The 502 case the endpoint was built for, and the control that keeps it
		// from collapsing into the 400s: the origin is reachable and broken, so
		// the next attempt genuinely may succeed.
		{"unreachable origin", fmt.Errorf("%w: dial tcp: connection refused", rampwellknown.ErrFetch), http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, body := postRegisterStubbed(t, stubRegistry{registerErr: tc.err}, map[string]string{
				"agent_id": "agent.example", "discovery_url": "https://agent.example",
			})
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d (error %q)", status, tc.wantStatus, body["error"])
			}
			permanent := tc.wantStatus == http.StatusBadRequest
			if agentreg.IsCallerFault(tc.err) != permanent {
				t.Errorf("this table calls %v permanent=%v, agentreg.IsCallerFault says %v; "+
					"the two must agree or one caller answers this fault differently from the others",
					tc.err, permanent, agentreg.IsCallerFault(tc.err))
			}
		})
	}
}

// TestAgentsRegister_AbsentDirectoryDoesNotBlameTheFetch is the message half of
// the case above. A 404 means the fetch SUCCEEDED — the origin was reached and
// answered. Reporting it as a failed fetch describes the caller's network, when
// what they have to do is publish the document at discovery_url.
func TestAgentsRegister_AbsentDirectoryDoesNotBlameTheFetch(t *testing.T) {
	t.Parallel()

	_, body := postRegisterStubbed(t, stubRegistry{registerErr: rampwellknown.ErrNoDocument}, map[string]string{
		"agent_id": "agent.example", "discovery_url": "https://agent.example",
	})
	if strings.Contains(body["error"], "failed to fetch") {
		t.Errorf("error %q blames the fetch; the origin answered, with 404", body["error"])
	}
	if !strings.Contains(body["error"], "no key directory") {
		t.Errorf("error %q does not say the document is absent", body["error"])
	}
}

// TestAgentsRegister_NotAHostIsNotReportedAsAMalformedManifest pins the
// diagnostic split. discovery_url is not canonicalized at the edge — only its
// anchoring to agent_id is decided, inside the registry — so a discovery_url that
// names no host surfaces here as agentreg.ErrNotAHost. It used to share
// ErrMalformedDirectory's arm and blame a malformed document on an
// unauthenticated public endpoint, sending the caller to inspect one the
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

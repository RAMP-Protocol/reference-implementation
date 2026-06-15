//go:build integration

package transport_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// registerFixture wires a real Postgres (via setupExchangeTestDB-style bootstrap),
// a real agentreg.Registry, a fixture agent origin publishing ramp.json,
// and an httptest server that serves the transport handler.
type registerFixture struct {
	ctx       context.Context
	queries   *sqlc.Queries
	registry  agentreg.Registry
	origin    *agentOrigin
	server    *httptest.Server
	handler   *transport.AgentsRegisterHandler
	now       time.Time
	agentID   string
	agentPub  ed25519.PublicKey
	agentPriv ed25519.PrivateKey
	rewriteMu *sync.Mutex
	rewrite   map[string]string
}

// agentOrigin serves an ed25519 key manifest for the fixture agent.
// statusOverride, when non-zero, short-circuits to a custom response code.
type agentOrigin struct {
	server         *httptest.Server
	mu             sync.Mutex
	agentID        string
	pub            ed25519.PublicKey
	validFrom      time.Time
	validUntil     time.Time
	statusOverride int
}

func newAgentOrigin(t *testing.T, agentID string, pub ed25519.PublicKey, now time.Time) *agentOrigin {
	t.Helper()
	o := &agentOrigin{
		agentID:    agentID,
		pub:        pub,
		validFrom:  now.Add(-time.Hour),
		validUntil: now.Add(24 * time.Hour),
	}
	o.server = httptest.NewServer(http.HandlerFunc(o.handle))
	t.Cleanup(o.server.Close)
	return o
}

func (o *agentOrigin) setStatus(code int) {
	o.mu.Lock()
	o.statusOverride = code
	o.mu.Unlock()
}

func (o *agentOrigin) handle(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	status := o.statusOverride
	agentID := o.agentID
	pub := o.pub
	from, until := o.validFrom, o.validUntil
	o.mu.Unlock()
	if status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	if r.URL.Path != "/.well-known/ramp.json" {
		http.NotFound(w, r)
		return
	}
	doc, err := agentManifestFields(agentID, pub, from, until)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

type registerFixedClock struct{ now time.Time }

func (c *registerFixedClock) Now() time.Time { return c.now }

func setupRegisterFixture(t *testing.T, opts transport.AgentsRegisterOptions) *registerFixture {
	t.Helper()
	ctx := context.Background()
	dsn := sharedb.StartPostgres(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool, err := sharedb.Setup(ctx, sharedb.SetupOptions{
		DSN:             dsn,
		Migrations:      exchangedb.Migrations,
		MigrationsDir:   exchangedb.MigrationsDir,
		MigrationsTable: exchangedb.MigrationsTable,
	}, logger)
	if err != nil {
		t.Fatalf("db setup: %v", err)
	}
	t.Cleanup(pool.Close)
	queries := sqlc.New(pool)

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	agentID := "agent.register.test"
	origin := newAgentOrigin(t, agentID, pub, now)
	rewriteMu := &sync.Mutex{}
	rewrite := map[string]string{agentID: origin.server.URL}

	registry := agentreg.New(agentreg.Config{
		Repo: repo.NewAgentRepo(queries),
		// Production fetches the manifest from agent_id's own host (ADR-009
		// D3/D4); the rewriting client routes that logical host to the fixture
		// origin so the test never feeds a real URL into production wiring.
		HTTP:  &http.Client{Transport: &rewritingTransport{base: http.DefaultTransport, mu: rewriteMu, rewrite: rewrite}},
		Clock: &registerFixedClock{now: now},
	})

	handler := transport.NewAgentsRegisterHandler(registry, opts)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	server := httptest.NewServer(transport.RequestIDMiddleware(logger, mux))
	t.Cleanup(server.Close)

	return &registerFixture{
		ctx: ctx, queries: queries, registry: registry,
		origin: origin, server: server, handler: handler, now: now,
		agentID: agentID, agentPub: pub, agentPriv: priv,
		rewriteMu: rewriteMu, rewrite: rewrite,
	}
}

func postRegister(t *testing.T, fx *registerFixture, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(fx.ctx, http.MethodPost,
		fx.server.URL+"/exchange/v1/agents/register",
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http do: %v", err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(raw) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode body %q: %v", string(raw), err)
	}
	return out
}

func TestAgentsRegister_HappyPathAndSignatureVerifies(t *testing.T) {
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{})
	body, _ := json.Marshal(map[string]string{
		"agent_id":     fx.agentID,
		"manifest_url": fx.agentID,
	})
	resp := postRegister(t, fx, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out := decodeBody(t, resp)
	if out["status"] != "registered" || out["agent_id"] != fx.agentID {
		t.Fatalf("body = %v", out)
	}

	row, err := fx.queries.GetAgent(fx.ctx, fx.agentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if !bytes.Equal(row.PublicKey, fx.agentPub) {
		t.Fatalf("stored pubkey does not match fixture agent pubkey")
	}

	// A subsequent message signed by the agent's private key verifies against
	// the key the Exchange just registered. This is the load-bearing check for
	// §7.2 — self-signup then transact.
	got, err := fx.registry.LookupPublicKey(fx.ctx, fx.agentID)
	if err != nil {
		t.Fatalf("LookupPublicKey: %v", err)
	}
	payload := []byte("discover-supply-canonical-bytes")
	sig := ed25519.Sign(fx.agentPriv, payload)
	if !ed25519.Verify(got, payload, sig) {
		t.Fatalf("signature did not verify with registered pubkey")
	}
}

func TestAgentsRegister_MethodNotAllowed(t *testing.T) {
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{})
	req, err := http.NewRequestWithContext(fx.ctx, http.MethodGet,
		fx.server.URL+"/exchange/v1/agents/register", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http do: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestAgentsRegister_MissingBody(t *testing.T) {
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{})
	resp := postRegister(t, fx, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	out := decodeBody(t, resp)
	if out["error"] == nil {
		t.Fatalf("error missing: %v", out)
	}
}

func TestAgentsRegister_MalformedJSON(t *testing.T) {
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{})
	resp := postRegister(t, fx, []byte("{not-json"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAgentsRegister_MissingFields(t *testing.T) {
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{})
	body, _ := json.Marshal(map[string]string{"agent_id": "some.agent"})
	resp := postRegister(t, fx, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAgentsRegister_BodyOverLimit(t *testing.T) {
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{MaxBodyBytes: 32})
	// 64 bytes of filler > 32 byte cap.
	body := []byte(`{"agent_id":"` + strings.Repeat("x", 64) + `","manifest_url":"y"}`)
	resp := postRegister(t, fx, body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestAgentsRegister_UpstreamFetchFailure(t *testing.T) {
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{})
	fx.origin.setStatus(http.StatusNotFound)
	body, _ := json.Marshal(map[string]string{
		"agent_id":     fx.agentID,
		"manifest_url": fx.agentID,
	})
	resp := postRegister(t, fx, body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	out := decodeBody(t, resp)
	if out["error"] == nil {
		t.Fatalf("missing error body: %v", out)
	}
}

func TestAgentsRegister_AgentIDMismatch(t *testing.T) {
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{})
	// Anchored host (manifest_url == agent_id), but the served manifest body
	// self-asserts a different domain → the domain-binding check rejects it.
	fx.rewriteMu.Lock()
	fx.rewrite["wrong.agent.id"] = fx.origin.server.URL
	fx.rewriteMu.Unlock()
	body, _ := json.Marshal(map[string]string{
		"agent_id":     "wrong.agent.id",
		"manifest_url": "wrong.agent.id",
	})
	resp := postRegister(t, fx, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAgentsRegister_RateLimit(t *testing.T) {
	// Burst=1 with a refill so slow the second call in the same window is
	// guaranteed to trip. Using an injected factory keeps the test
	// deterministic — no wall-clock dependency.
	fx := setupRegisterFixture(t, transport.AgentsRegisterOptions{
		LimiterFactory: func() *rate.Limiter {
			return rate.NewLimiter(rate.Every(time.Hour), 1)
		},
	})
	body, _ := json.Marshal(map[string]string{
		"agent_id":     fx.agentID,
		"manifest_url": fx.agentID,
	})
	resp1 := postRegister(t, fx, body)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first call status = %d, want 200", resp1.StatusCode)
	}
	_ = resp1.Body.Close()
	resp2 := postRegister(t, fx, body)
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second call status = %d, want 429", resp2.StatusCode)
	}
	_ = resp2.Body.Close()
}

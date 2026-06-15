//go:build integration

package agentreg_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time { return c.now }

// fixtureKey describes one Ed25519 key to publish in the unified AGENT
// manifest, with a half-open [validFrom, validUntil) validity window.
type fixtureKey struct {
	kid        string
	pub        ed25519.PublicKey
	validFrom  time.Time
	validUntil time.Time
}

type fixtureOrigin struct {
	server  *httptest.Server
	mu      sync.Mutex
	agentID string
	keys    []fixtureKey
}

func newFixtureOrigin(t *testing.T, agentID string, keys []fixtureKey) *fixtureOrigin {
	t.Helper()
	o := &fixtureOrigin{agentID: agentID, keys: keys}
	o.server = httptest.NewServer(http.HandlerFunc(o.handle))
	t.Cleanup(o.server.Close)
	return o
}

func (o *fixtureOrigin) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/ramp.json" {
		http.NotFound(w, r)
		return
	}
	o.mu.Lock()
	agentID := o.agentID
	keys := append([]fixtureKey(nil), o.keys...)
	o.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(agentManifestJSON(agentID, keys))
}

func (o *fixtureOrigin) setKeys(agentID string, keys []fixtureKey) {
	o.mu.Lock()
	o.agentID = agentID
	o.keys = keys
	o.mu.Unlock()
}

func mustEd25519(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	return pub
}

// hostRewriter routes requests whose URL host is a registered agent identity to
// the test origin serving that agent's manifest. Production fetches the manifest
// from agent_id's own host (ADR-009 D3/D4); the rewriter lets the test bind a
// logical agent_id to an ephemeral httptest server without DNS, mirroring the
// transport harness's registerHost pattern.
type hostRewriter struct {
	mu      sync.Mutex
	targets map[string]string // agent host → "http://127.0.0.1:port"
}

func newHostRewriter() *hostRewriter { return &hostRewriter{targets: map[string]string{}} }

func (h *hostRewriter) set(host, target string) {
	h.mu.Lock()
	h.targets[host] = target
	h.mu.Unlock()
}

func (h *hostRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	h.mu.Lock()
	target, ok := h.targets[req.URL.Host]
	h.mu.Unlock()
	if ok {
		t, err := url.Parse(target)
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.URL.Scheme = t.Scheme
		req.URL.Host = t.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

func setupRegistry(t *testing.T, clock agentreg.Clock) (agentreg.Registry, *sqlc.Queries, *hostRewriter) {
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
	q := sqlc.New(pool)
	rw := newHostRewriter()
	reg := agentreg.New(agentreg.Config{
		Repo:  repo.NewAgentRepo(q),
		HTTP:  &http.Client{Transport: rw},
		Clock: clock,
	})
	return reg, q, rw
}

func TestRegistry_HappyPath(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	reg, q, rw := setupRegistry(t, &fixedClock{now: now})
	ctx := t.Context()

	pub := mustEd25519(t)
	agentID := "agent.fixture.test"
	origin := newFixtureOrigin(t, agentID, []fixtureKey{{
		kid: "k1", pub: pub,
		validFrom:  now.Add(-time.Hour),
		validUntil: now.Add(24 * time.Hour),
	}})
	rw.set(agentID, origin.server.URL)

	if err := reg.RegisterFromManifest(ctx, agentID, agentID); err != nil {
		t.Fatalf("register: %v", err)
	}
	got, err := reg.LookupPublicKey(ctx, agentID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !pub.Equal(got) {
		t.Fatalf("lookup key mismatch")
	}

	row, err := q.GetAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	// The stored manifest_url is the identity-anchored discovery URL derived from
	// agent_id, not whatever the caller passed.
	wantURL, _ := rampwellknown.ManifestURL(agentID, "", "")
	if !row.ManifestUrl.Valid || row.ManifestUrl.String != wantURL {
		t.Fatalf("manifest_url = %+v, want %q", row.ManifestUrl, wantURL)
	}
}

func TestRegistry_ManifestURLNotAnchored(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	reg, q, rw := setupRegistry(t, &fixedClock{now: now})
	ctx := t.Context()

	// An attacker-controlled origin self-asserts domain == victim agent_id.
	pub := mustEd25519(t)
	const victimID = "agent.fixture.test"
	origin := newFixtureOrigin(t, victimID, []fixtureKey{{
		kid: "k1", pub: pub,
		validFrom:  now.Add(-time.Hour),
		validUntil: now.Add(24 * time.Hour),
	}})
	rw.set("attacker.example", origin.server.URL)

	// Registering victimID against a manifest_url hosted by attacker.example must
	// be refused before any fetch — discovery is anchored to agent_id (ADR-009).
	err := reg.RegisterFromManifest(ctx, victimID, "https://attacker.example/.well-known/ramp.json")
	if !errors.Is(err, agentreg.ErrAgentIDMismatch) {
		t.Fatalf("want ErrAgentIDMismatch for unanchored manifest_url, got %v", err)
	}
	if _, err := q.GetAgent(ctx, victimID); err == nil {
		t.Fatal("victim agent must not be registered from an unanchored host")
	}
}

func TestRegistry_AgentIDMismatch(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	reg, q, rw := setupRegistry(t, &fixedClock{now: now})
	ctx := t.Context()

	pub := mustEd25519(t)
	// The manifest is correctly anchored to agent.fixture.test's host, but its
	// body self-asserts a different domain → the domain-binding check rejects it.
	origin := newFixtureOrigin(t, "other.agent.test", []fixtureKey{{
		kid: "k1", pub: pub,
		validFrom:  now.Add(-time.Hour),
		validUntil: now.Add(24 * time.Hour),
	}})
	rw.set("agent.fixture.test", origin.server.URL)

	err := reg.RegisterFromManifest(ctx, "agent.fixture.test", "agent.fixture.test")
	if !errors.Is(err, agentreg.ErrAgentIDMismatch) {
		t.Fatalf("want ErrAgentIDMismatch, got %v", err)
	}

	if _, err := reg.LookupPublicKey(ctx, "agent.fixture.test"); !errors.Is(err, agentreg.ErrUnknown) {
		t.Fatalf("expected ErrUnknown post-mismatch, got %v", err)
	}
	if _, err := q.GetAgent(ctx, "agent.fixture.test"); err == nil {
		t.Fatalf("unexpected row for mismatched agent")
	}
}

func TestRegistry_MultipleKeysPicksCurrent(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	reg, _, rw := setupRegistry(t, &fixedClock{now: now})
	ctx := t.Context()

	oldPub := mustEd25519(t)
	currentPub := mustEd25519(t)
	futurePub := mustEd25519(t)
	agentID := "agent.rotate.test"

	origin := newFixtureOrigin(t, agentID, []fixtureKey{
		{
			kid: "old", pub: oldPub,
			validFrom:  now.Add(-72 * time.Hour),
			validUntil: now.Add(-1 * time.Hour),
		},
		{
			kid: "current", pub: currentPub,
			validFrom:  now.Add(-1 * time.Hour),
			validUntil: now.Add(24 * time.Hour),
		},
		{
			kid: "future", pub: futurePub,
			validFrom:  now.Add(24 * time.Hour),
			validUntil: now.Add(48 * time.Hour),
		},
	})
	rw.set(agentID, origin.server.URL)

	if err := reg.RegisterFromManifest(ctx, agentID, agentID); err != nil {
		t.Fatalf("register: %v", err)
	}
	got, err := reg.LookupPublicKey(ctx, agentID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !currentPub.Equal(got) {
		t.Fatalf("wrong key selected; want current key")
	}
}

func TestRegistry_UpsertIdempotentAndKeyReplace(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	reg, q, rw := setupRegistry(t, &fixedClock{now: now})
	ctx := t.Context()

	pubV1 := mustEd25519(t)
	agentID := "agent.idem.test"
	origin := newFixtureOrigin(t, agentID, []fixtureKey{{
		kid: "v1", pub: pubV1,
		validFrom:  now.Add(-time.Hour),
		validUntil: now.Add(24 * time.Hour),
	}})
	rw.set(agentID, origin.server.URL)

	if err := reg.RegisterFromManifest(ctx, agentID, agentID); err != nil {
		t.Fatalf("register1: %v", err)
	}
	row1, err := q.GetAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("GetAgent1: %v", err)
	}

	if err := reg.RegisterFromManifest(ctx, agentID, agentID); err != nil {
		t.Fatalf("register2: %v", err)
	}
	row2, err := q.GetAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("GetAgent2: %v", err)
	}
	if !bytesEqual(row1.PublicKey, row2.PublicKey) {
		t.Fatalf("idempotent upsert mutated key bytes")
	}
	if !row1.RegisteredAt.Time.Equal(row2.RegisteredAt.Time) {
		t.Fatalf("registered_at changed across idempotent upserts: %v -> %v",
			row1.RegisteredAt.Time, row2.RegisteredAt.Time)
	}

	pubV2 := mustEd25519(t)
	origin.setKeys(agentID, []fixtureKey{{
		kid: "v2", pub: pubV2,
		validFrom:  now.Add(-time.Hour),
		validUntil: now.Add(24 * time.Hour),
	}})
	if err := reg.RegisterFromManifest(ctx, agentID, agentID); err != nil {
		t.Fatalf("register3: %v", err)
	}
	row3, err := q.GetAgent(ctx, agentID)
	if err != nil {
		t.Fatalf("GetAgent3: %v", err)
	}
	if bytesEqual(row3.PublicKey, row1.PublicKey) {
		t.Fatalf("expected new kid to replace stored key bytes")
	}
	gotPub, err := reg.LookupPublicKey(ctx, agentID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !pubV2.Equal(gotPub) {
		t.Fatalf("lookup did not return replacement key")
	}
}

func TestRegistry_LookupUnknown(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	reg, _, _ := setupRegistry(t, &fixedClock{now: now})

	_, err := reg.LookupPublicKey(t.Context(), "agent.nobody.test")
	if !errors.Is(err, agentreg.ErrUnknown) {
		t.Fatalf("want ErrUnknown, got %v", err)
	}
}

// TestRegistry_NilHTTPClientDefaultsToGuardedClient pins the constructor's
// fail-safe default: with no explicit HTTP client, agentreg.New must fall back
// to the SSRF-guarded env client (like every sibling fetch constructor), never
// http.DefaultClient. agents/register is an unauthenticated, caller-controlled
// (agent_id + manifest_url) fetch path, so an unguarded default would let a
// caller drive a fetch at a loopback/link-local/metadata target.
//
// The guard refuses to dial a non-public address at connect time, so pointing a
// registration at a loopback origin yields ErrBlockedTarget. With the unguarded
// default the same dial would instead reach the origin (a TLS error, not a
// block), so this assertion fails closed against a regression.
func TestRegistry_NilHTTPClientDefaultsToGuardedClient(t *testing.T) {
	// Force the production-safe guard posture regardless of the ambient
	// compose/dev flag, so the loopback dial is refused deterministically.
	t.Setenv(rampwellknown.EnvInsecureAllowPrivate, "0")
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_, q, _ := setupRegistry(t, &fixedClock{now: now})
	ctx := t.Context()

	// A real loopback listener reserves a 127.0.0.1:port the registry would
	// dial; its served body never matters because the guard blocks the connect.
	origin := newFixtureOrigin(t, "irrelevant.test", nil)
	u, err := url.Parse(origin.server.URL)
	if err != nil {
		t.Fatalf("parse origin url: %v", err)
	}
	loopbackID := u.Host // 127.0.0.1:PORT

	reg := agentreg.New(agentreg.Config{
		Repo:  repo.NewAgentRepo(q),
		Clock: &fixedClock{now: now},
	})
	err = reg.RegisterFromManifest(ctx, loopbackID, loopbackID)
	if !errors.Is(err, rampwellknown.ErrBlockedTarget) {
		t.Fatalf("nil HTTP client must default to the SSRF-guarded client and refuse "+
			"a loopback target; got %v", err)
	}
	if _, err := q.GetAgent(ctx, loopbackID); err == nil {
		t.Fatal("a guard-blocked registration must not persist an agent row")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// agentManifestJSON renders the unified ROLE_AGENT well-known manifest
// (protojson, snake_case) whose domain anchors agentID and whose public_keys
// carry the supplied Ed25519 keys. The shared rampwellknown producer helpers
// guarantee the JWK shape matches what the consumer library accepts.
func agentManifestJSON(agentID string, keys []fixtureKey) []byte {
	jwks := make([]*rampwellknown.Key, 0, len(keys))
	for _, k := range keys {
		jwks = append(jwks, rampwellknown.NewKey(k.kid, k.pub, k.validFrom, k.validUntil))
	}
	return testutil.MarshalManifest(testutil.Manifest(rampwellknown.RoleAgent, agentID, jwks...))
}

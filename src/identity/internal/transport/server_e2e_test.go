//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/transport"
)

const baseZone = "rampmcp.org"

// fixture is one wired directory server over the shared backends, isolated per
// test (Vault mount reset + Postgres restore before it is built).
//
// Test state is arranged through the production write surfaces this service owns —
// store.Create (KeyStore) and cards.Upsert (card repo) — not raw Vault/SQL, per
// Testing Doctrine 9. There is no PUBLIC (RPC/HTTP) write surface to arrange
// through yet: developer sign-up is what will create keys and write
// cards over the wire. Until it lands, the repo/keystore surfaces are the
// sanctioned tier-2 fallback. Once a public sign-up write surface exists,
// re-arrange these through it.
type fixture struct {
	srv         *httptest.Server
	svc         *publisher.Service
	store       keystore.KeyStore
	cards       *repo.PgxCardRepo
	revocations *repo.PgxRevocationRepo
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := t.Context()
	if err := sharedVault.Reset(ctx); err != nil {
		t.Fatalf("reset vault: %v", err)
	}
	pool := acquireTestDB(t, ctx)

	store, err := keystore.NewVaultStore(keystore.Config{
		Client: sharedVault.Client,
		Mount:  sharedVault.Mount,
		Clk:    clock.System{},
	})
	if err != nil {
		t.Fatalf("new vault store: %v", err)
	}
	cards := repo.NewCardRepo(pool)
	revocations := repo.NewRevocationRepo(pool)
	svc, err := publisher.New(publisher.Config{
		Keys: store, Cards: cards, Revocations: revocations, Clock: clock.System{},
	})
	if err != nil {
		t.Fatalf("publisher.New: %v", err)
	}
	handler := transport.NewHandler(baseZone, svc, publisher.DefaultTTL)

	// Drive the real production chain (request-id middleware, /healthz, host
	// dispatch), not a hand-rolled mux, so the middleware and headers are exercised.
	srv := httptest.NewServer(transport.NewServer(testutil.DiscardLogger(), handler, func(context.Context) error { return nil }))
	t.Cleanup(srv.Close)

	return &fixture{srv: srv, svc: svc, store: store, cards: cards, revocations: revocations}
}

// getForHost issues GET path with the given Host header (which drives dispatch)
// and returns the status, content-type, and body.
func (f *fixture) getForHost(t *testing.T, host, path string) (int, string, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), body
}

func validWindow() keystore.Window {
	now := time.Now().UTC()
	return keystore.Window{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
}

func mustCreate(t *testing.T, store keystore.KeyStore, subdomain string) keystore.Key {
	t.Helper()
	k, err := store.Create(t.Context(), subdomain, validWindow())
	if err != nil {
		t.Fatalf("create key %q: %v", subdomain, err)
	}
	return k
}

// TestDirectoryAdvertisesDiscoverableRevocationURL drives the discovery leg a WBA
// consumer actually walks: fetch the directory, read its revocation_url, and fetch
// THAT back to the same server. Two agents on the wildcard zone are driven because
// the consumer (rampwellknown.Loader) host-anchors the advertised URL and skips a
// cross-host one — a single shared/static revocation_url could anchor to at most one
// of them, silently leaving the other's revocation list unpolled (fail-open). The
// existing revocation e2e fetches RevocationPath directly by Host; this one asserts
// the directory itself steers a consumer there.
func TestDirectoryAdvertisesDiscoverableRevocationURL(t *testing.T) {
	f := newFixture(t)
	for _, label := range []string{"agent-123", "agent-456"} {
		sub := label + "." + baseZone
		mustCreate(t, f.store, sub)

		status, _, body := f.getForHost(t, sub, rampwellknown.WBAPath)
		if status != http.StatusOK {
			t.Fatalf("%s: directory status = %d, want 200", sub, status)
		}
		var doc struct {
			RevocationURL string `json:"revocation_url"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("%s: parse directory: %v", sub, err)
		}
		if doc.RevocationURL == "" {
			t.Fatalf("%s: directory advertises no revocation_url — the revocation list is undiscoverable", sub)
		}
		anchored, err := rampwellknown.HostAnchored(sub, doc.RevocationURL)
		if err != nil {
			t.Fatalf("%s: HostAnchored(%q): %v", sub, doc.RevocationURL, err)
		}
		if !anchored {
			t.Fatalf("%s: revocation_url %q is not host-anchored to the directory; a consumer would skip the poll", sub, doc.RevocationURL)
		}
		// Walk the advertised URL's path back to the same server: it must resolve to
		// this agent's revocation list, closing the directory→revocation_url→list loop.
		u, err := url.Parse(doc.RevocationURL)
		if err != nil {
			t.Fatalf("%s: parse revocation_url %q: %v", sub, doc.RevocationURL, err)
		}
		revStatus, ctype, revBody := f.getForHost(t, sub, u.Path)
		if revStatus != http.StatusOK {
			t.Fatalf("%s: advertised revocation_url path %q status = %d, want 200", sub, u.Path, revStatus)
		}
		if ctype != directory.RevocationMediaType {
			t.Fatalf("%s: revocation content-type = %q, want %q", sub, ctype, directory.RevocationMediaType)
		}
		if len(revBody) == 0 {
			t.Fatalf("%s: advertised revocation_url returned an empty body", sub)
		}
	}
}

func TestServesWBAForFreshSubdomain(t *testing.T) {
	f := newFixture(t)
	sub := "agent-123." + baseZone
	created := mustCreate(t, f.store, sub)

	status, ctype, body := f.getForHost(t, sub, rampwellknown.WBAPath)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if ctype != directory.WBAMediaType {
		t.Errorf("content-type = %q, want %q", ctype, directory.WBAMediaType)
	}
	if err := rampwellknown.ValidateWBA(body); err != nil {
		t.Fatalf("served bytes fail schema: %v", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("go-jose parse over the wire: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	got, ok := set.Keys[0].Key.(ed25519.PublicKey)
	if !ok || !got.Equal(created.Public) {
		t.Fatal("served key does not match the created key")
	}
}

func TestServesCardForFreshSubdomain(t *testing.T) {
	f := newFixture(t)
	sub := "agent-123." + baseZone
	mustCreate(t, f.store, sub) // an agent exists
	want := directory.Card{ClientName: "Acme", ClientURI: "https://" + sub, Purpose: "ai-index"}
	if _, err := f.cards.Upsert(t.Context(), sub, want); err != nil {
		t.Fatalf("upsert card: %v", err)
	}

	status, ctype, body := f.getForHost(t, sub, directory.CardPath)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if ctype != directory.CardMediaType {
		t.Errorf("content-type = %q, want %q", ctype, directory.CardMediaType)
	}
	var got directory.Card
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("parse card: %v", err)
	}
	if got.ClientURI != want.ClientURI || got.ClientName != want.ClientName || got.Purpose != want.Purpose {
		t.Errorf("served card = %+v, want %+v", got, want)
	}
}

func TestWBAOrderMatchesStoreList(t *testing.T) {
	f := newFixture(t)
	sub := "agent-multi." + baseZone
	mustCreate(t, f.store, sub)
	mustCreate(t, f.store, sub)

	// The served order MUST equal the store's List order (load-bearing: a consumer
	// without a known thumbprint takes the first active key in document order).
	listed, err := f.store.List(t.Context(), sub)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	wantX := make([]string, len(listed))
	for i, k := range listed {
		wantX[i] = rampwellknown.EncodeEd25519X(k.Public)
	}

	_, _, body := f.getForHost(t, sub, rampwellknown.WBAPath)
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Keys) != len(wantX) {
		t.Fatalf("served %d keys, want %d", len(doc.Keys), len(wantX))
	}
	for i, want := range wantX {
		if doc.Keys[i]["x"] != want {
			t.Errorf("served key[%d].x = %v, want %v (order not preserved)", i, doc.Keys[i]["x"], want)
		}
	}
}

func TestUnknownHostsAre404(t *testing.T) {
	f := newFixture(t)
	// Provision one real agent so "not found" is genuinely per-host, not a dead server.
	mustCreate(t, f.store, "agent-123."+baseZone)

	cases := []struct {
		name, host string
	}{
		{"no keys, no card", "nope." + baseZone},
		{"apex zone", baseZone},
		{"multi-label child", "a.b." + baseZone},
		{"foreign domain", "evil.example.com"},
		{"malformed label (grammar reject)", "bad_label." + baseZone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []string{rampwellknown.WBAPath, directory.CardPath, rampwellknown.RevocationPath} {
				status, _, _ := f.getForHost(t, tc.host, path)
				if status != http.StatusNotFound {
					t.Errorf("GET %s Host=%s: status = %d, want 404", path, tc.host, status)
				}
			}
		})
	}
}

func TestCardAbsentWhenNoRow(t *testing.T) {
	f := newFixture(t)
	sub := "agent-keysonly." + baseZone
	mustCreate(t, f.store, sub) // keys but no card row

	if status, _, _ := f.getForHost(t, sub, rampwellknown.WBAPath); status != http.StatusOK {
		t.Errorf("WBA status = %d, want 200 (keys exist)", status)
	}
	if status, _, _ := f.getForHost(t, sub, directory.CardPath); status != http.StatusNotFound {
		t.Errorf("card status = %d, want 404 (no card row)", status)
	}
}

func TestInvalidateRebuildsAfterKeyChange(t *testing.T) {
	f := newFixture(t)
	sub := "agent-rot." + baseZone
	mustCreate(t, f.store, sub)

	// Warm the cache with one key.
	if n := servedKeyCount(t, f, sub); n != 1 {
		t.Fatalf("initial served keys = %d, want 1", n)
	}
	// Add a second key; the cached document still shows one until invalidated.
	mustCreate(t, f.store, sub)
	if n := servedKeyCount(t, f, sub); n != 1 {
		t.Fatalf("served keys after add (pre-invalidate) = %d, want 1 (cached)", n)
	}
	f.svc.Invalidate(sub)
	if n := servedKeyCount(t, f, sub); n != 2 {
		t.Fatalf("served keys after invalidate = %d, want 2", n)
	}
}

// TestPerAgentIsolation is the ticket's headline criterion: one agent never serves
// another's bytes, even with a warm cache. Warming agent-a and then fetching agent-b
// is what a naive shared/miskeyed cache would fail.
func TestPerAgentIsolation(t *testing.T) {
	f := newFixture(t)
	subA, subB := "agent-a."+baseZone, "agent-b."+baseZone
	keyA := mustCreate(t, f.store, subA)
	keyB := mustCreate(t, f.store, subB)
	if _, err := f.cards.Upsert(t.Context(), subA, directory.Card{ClientName: "A", ClientURI: "https://" + subA}); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	if _, err := f.cards.Upsert(t.Context(), subB, directory.Card{ClientName: "B", ClientURI: "https://" + subB}); err != nil {
		t.Fatalf("upsert B: %v", err)
	}

	// Warm A's cache entry first, then ask for B.
	f.getForHost(t, subA, rampwellknown.WBAPath)
	_, _, bodyB := f.getForHost(t, subB, rampwellknown.WBAPath)

	xs := directoryXValues(t, bodyB)
	xA := rampwellknown.EncodeEd25519X(keyA.Public)
	xB := rampwellknown.EncodeEd25519X(keyB.Public)
	if !contains(xs, xB) {
		t.Error("agent-b's directory is missing its own key")
	}
	if contains(xs, xA) {
		t.Error("agent-b's directory leaked agent-a's key")
	}

	_, _, cardBody := f.getForHost(t, subB, directory.CardPath)
	var card directory.Card
	if err := json.Unmarshal(cardBody, &card); err != nil {
		t.Fatalf("parse B card: %v", err)
	}
	if card.ClientURI != "https://"+subB {
		t.Errorf("agent-b's card = %q, want its own (not agent-a's)", card.ClientURI)
	}
}

// TestInvalidateIsolatesSubdomains proves Invalidate touches exactly one agent.
func TestInvalidateIsolatesSubdomains(t *testing.T) {
	f := newFixture(t)
	subA, subB := "agent-a."+baseZone, "agent-b."+baseZone
	mustCreate(t, f.store, subA)
	mustCreate(t, f.store, subB)
	// Warm both cache entries.
	_ = servedKeyCount(t, f, subA)
	_ = servedKeyCount(t, f, subB)

	mustCreate(t, f.store, subA) // rotate A
	f.svc.Invalidate(subA)

	if n := servedKeyCount(t, f, subA); n != 2 {
		t.Fatalf("agent-a served %d keys after invalidate, want 2", n)
	}
	if n := servedKeyCount(t, f, subB); n != 1 {
		t.Fatalf("agent-b served %d keys, want 1 (must be untouched by A's invalidate)", n)
	}
}

// TestServerChain drives the real production handler (NewServer): /healthz and the
// X-Request-ID header Architecture Rule 8 requires on every response.
func TestServerChain(t *testing.T) {
	f := newFixture(t)

	healthReq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+"/healthz", nil)
	resp, err := f.srv.Client().Do(healthReq)
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}

	sub := "agent-123." + baseZone
	mustCreate(t, f.store, sub)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+rampwellknown.WBAPath, nil)
	req.Host = sub
	resp2, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("directory request: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.Header.Get("X-Request-ID") == "" {
		t.Error("response missing X-Request-ID (middleware chain not exercised)")
	}
}

func directoryXValues(t *testing.T, body []byte) []string {
	t.Helper()
	var doc struct {
		Keys []struct {
			X string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse directory: %v", err)
	}
	xs := make([]string, len(doc.Keys))
	for i, k := range doc.Keys {
		xs[i] = k.X
	}
	return xs
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func servedKeyCount(t *testing.T, f *fixture, host string) int {
	t.Helper()
	_, _, body := f.getForHost(t, host, rampwellknown.WBAPath)
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return len(doc.Keys)
}

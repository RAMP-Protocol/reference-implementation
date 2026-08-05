package server_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	jose "github.com/go-jose/go-jose/v4"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

var anchor = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

func oneKey(seed string) (server.KeySource, *rampwellknown.Key) {
	_, k := testutil.NewSigningKey(seed, anchor.Add(-time.Hour), anchor.Add(time.Hour))
	return server.StaticKeys(k), k
}

func TestBuild_RolesRoundTrip(t *testing.T) {
	t.Parallel()
	hops := int32(4)
	cfgs := map[string]server.Config{
		"agent":  {Role: rampwellknown.RoleAgent, Domain: "a.example"},
		"broker": {Role: rampwellknown.RoleBroker, Domain: "b.example"},
		"exchange": {
			Role: rampwellknown.RoleExchange, Domain: "x.example",
			Endpoint: "https://x.example/ramp", BaseCurrency: "USD", MaxIntermediaryHops: &hops,
		},
		"publisher": {
			Role: rampwellknown.RolePublisher, Domain: "p.example",
			Exchanges: []*rampv1.AuthorizedExchange{
				testutil.PublisherExchange("x.example", "https://x.example/ramp",
					rampv1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT),
			},
		},
	}
	want := map[string]rampwellknown.Role{
		"agent": rampwellknown.RoleAgent, "broker": rampwellknown.RoleBroker,
		"exchange": rampwellknown.RoleExchange, "publisher": rampwellknown.RolePublisher,
	}
	for name, cfg := range cfgs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := server.Build(cfg)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			m, err := rampwellknown.ParseManifest(raw, want[name])
			if err != nil {
				t.Fatalf("ParseManifest: %v", err)
			}
			if m.GetDomain() != cfg.Domain {
				t.Fatalf("domain=%s want %s", m.GetDomain(), cfg.Domain)
			}
		})
	}
}

func TestBuildWBA_RoundTrip(t *testing.T) {
	t.Parallel()
	src, key := oneKey("x")
	raw, err := server.BuildWBA(server.WBAConfig{Keys: src, RevocationURL: "https://x.example/rev.json"})
	if err != nil {
		t.Fatalf("BuildWBA: %v", err)
	}
	f, err := rampwellknown.ParseWBA(raw)
	if err != nil {
		t.Fatalf("ParseWBA: %v", err)
	}
	if f.GetRevocationUrl() != "https://x.example/rev.json" {
		t.Fatalf("revocation_url not carried: %q", f.GetRevocationUrl())
	}
	if _, ok := rampwellknown.KeyByThumbprint(f, testutil.MustThumbprintKey(t, key)); !ok {
		t.Fatal("built WBA directory missing the key")
	}
}

// TestBuildWBA_GoJoseInterop is the acceptance-criterion interop check: the
// bytes the WBA producer emits must be readable by an off-the-shelf JOSE library
// (go-jose JSONWebKeySet.UnmarshalJSON), not merely by RAMP's own ParseWBA — the
// whole point of the pure-WBA split. It also pins that the RAMP-specific validity
// members (not_before/not_after) the producer carries do not break a standard
// JWK-Set parse.
func TestBuildWBA_GoJoseInterop(t *testing.T) {
	t.Parallel()
	priv, key := testutil.NewSigningKey("interop", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	raw, err := server.BuildWBA(server.WBAConfig{
		Keys:          server.StaticKeys(key),
		RevocationURL: "https://x.example/rev.json",
	})
	if err != nil {
		t.Fatalf("BuildWBA: %v", err)
	}

	// Off-the-shelf parse: decode the raw bytes straight into go-jose's
	// JSONWebKeySet via encoding/json (the same path production uses in
	// httpsig.keyresolver), which invokes go-jose's per-key JWK unmarshaller.
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("off-the-shelf go-jose could not parse the WBA directory: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("go-jose parsed %d keys, want 1", len(set.Keys))
	}
	pub, ok := set.Keys[0].Key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("go-jose key type = %T, want ed25519.PublicKey", set.Keys[0].Key)
	}
	if want, _ := priv.Public().(ed25519.PublicKey); !pub.Equal(want) {
		t.Fatal("go-jose parsed a key that does not match the producer's signing key")
	}
}

func TestBuildWBA_NoKeysRejected(t *testing.T) {
	t.Parallel()
	if _, err := server.BuildWBA(server.WBAConfig{}); err == nil {
		t.Fatal("expected a WBA directory with no keys to fail schema validation")
	}
}

func TestHandler_ServeManifest(t *testing.T) {
	t.Parallel()
	h, err := server.NewHandler(server.Config{Role: rampwellknown.RoleBroker, Domain: "b.example"})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + rampwellknown.Path) //nolint:noctx // test client
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if _, err := rampwellknown.ParseManifest(body, rampwellknown.RoleBroker); err != nil {
		t.Fatalf("served manifest invalid: %v", err)
	}
}

// mutableKeys is a KeySource whose key list can be rotated between Rebuilds, so
// the test can prove Rebuild actually re-reads the source.
type mutableKeys struct{ keys []*rampwellknown.Key }

func (m *mutableKeys) Keys() []*rampwellknown.Key { return m.keys }

func TestWBAHandler_ServeAndRebuild(t *testing.T) {
	t.Parallel()
	_, b1 := testutil.NewSigningKey("b1", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	src := &mutableKeys{keys: []*rampwellknown.Key{b1}}
	h, err := server.NewWBAHandler(server.WBAConfig{Keys: src})
	if err != nil {
		t.Fatalf("NewWBAHandler: %v", err)
	}
	// Serve through a mux mounted at the WBA path (exercises RegisterRoutes).
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + rampwellknown.WBAPath) //nolint:noctx // test client
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/jwk-set+json" {
		t.Fatalf("WBA content-type = %q, want application/jwk-set+json", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	served, err := rampwellknown.ParseWBA(body)
	if err != nil {
		t.Fatalf("served WBA directory invalid: %v", err)
	}
	if _, ok := rampwellknown.KeyByThumbprint(served, testutil.MustThumbprintKey(t, b1)); !ok {
		t.Fatal("initial document missing key b1")
	}

	// Rotate the KeySource, then Rebuild: the new key must replace the old one,
	// proving Rebuild re-reads the source rather than serving a stale snapshot.
	_, b2 := testutil.NewSigningKey("b2", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	src.keys = []*rampwellknown.Key{b2}
	if err := h.Rebuild(); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	rebuilt, err := rampwellknown.ParseWBA(h.Bytes())
	if err != nil {
		t.Fatalf("WBA directory invalid after rebuild: %v", err)
	}
	if _, ok := rampwellknown.KeyByThumbprint(rebuilt, testutil.MustThumbprintKey(t, b2)); !ok {
		t.Fatal("Rebuild did not pick up the rotated-in key b2")
	}
	if _, ok := rampwellknown.KeyByThumbprint(rebuilt, testutil.MustThumbprintKey(t, b1)); ok {
		t.Fatal("Rebuild still serves the old key b1 after rotation")
	}
}

// lockedKeys is a KeySource safe to rotate while RunRefresher reads it from
// another goroutine.
type lockedKeys struct {
	mu   sync.Mutex
	keys []*rampwellknown.Key
}

func (m *lockedKeys) Keys() []*rampwellknown.Key {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys
}

func (m *lockedKeys) set(keys ...*rampwellknown.Key) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = keys
}

// recordCounter is a slog.Handler that only counts records, so the test can
// wait until the refresher has attempted (and failed) at least one rebuild.
type recordCounter struct{ n atomic.Int64 }

func (c *recordCounter) Enabled(context.Context, slog.Level) bool  { return true }
func (c *recordCounter) Handle(context.Context, slog.Record) error { c.n.Add(1); return nil }
func (c *recordCounter) WithAttrs([]slog.Attr) slog.Handler        { return c }
func (c *recordCounter) WithGroup(string) slog.Handler             { return c }

// TestRunRefresher_FailedRebuildKeepsServingOldDocument pins the refresher's
// failure behavior: when a rebuild fails (here: the KeySource rotates to an
// empty list, which the WBA schema rejects), the previously served bytes stay
// up and the loop keeps running — it logs a warning per failed attempt and
// recovers on its own once the source is healthy again. The surface never
// goes dark because one rebuild attempt failed.
func TestRunRefresher_FailedRebuildKeepsServingOldDocument(t *testing.T) {
	t.Parallel()
	_, good := testutil.NewSigningKey("keep-serving", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	src := &lockedKeys{keys: []*rampwellknown.Key{good}}
	wba, err := server.NewWBAHandler(server.WBAConfig{Keys: src})
	if err != nil {
		t.Fatalf("NewWBAHandler: %v", err)
	}
	manifest, err := server.NewHandler(server.Config{Role: rampwellknown.RoleBroker, Domain: "broker.example"})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h := server.Handlers{Manifest: manifest, WBA: wba}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	servedKeys := func() *rampwellknown.WBAFile {
		resp, err := http.Get(srv.URL + rampwellknown.WBAPath) //nolint:noctx // test client
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		f, err := rampwellknown.ParseWBA(body)
		if err != nil {
			t.Fatalf("served WBA directory invalid: %v", err)
		}
		return f
	}
	goodTP := testutil.MustThumbprintKey(t, good)
	if _, ok := rampwellknown.KeyByThumbprint(servedKeys(), goodTP); !ok {
		t.Fatal("initial document missing its key")
	}

	// Break the source: an empty key list fails BuildWBA's schema validation,
	// so every rebuild attempt from here on errors.
	src.set()
	counter := &recordCounter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.RunRefresher(ctx, time.Millisecond, slog.New(counter))

	deadline := time.Now().Add(5 * time.Second)
	for counter.n.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("refresher never logged a failed rebuild")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := rampwellknown.KeyByThumbprint(servedKeys(), goodTP); !ok {
		t.Fatal("failed rebuilds must keep the previously served document up, but the key is gone")
	}

	// Heal the source: the loop must still be running and pick the new key up
	// without intervention — a failure is a skipped tick, not an exit.
	_, healed := testutil.NewSigningKey("healed", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	src.set(healed)
	healedTP := testutil.MustThumbprintKey(t, healed)
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, ok := rampwellknown.KeyByThumbprint(servedKeys(), healedTP); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("refresher never recovered after the source turned healthy again")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

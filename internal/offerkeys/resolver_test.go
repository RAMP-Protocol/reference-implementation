package offerkeys

// Integration-shaped test: the resolver fetches a REAL WBA directory served by
// an httptest server (the adapter boundary — the exchange is the external
// system here), selects the active key, and caches it for the TTL.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

func wbaBodyWindow(t *testing.T, pub ed25519.PublicKey, notBefore, notAfter string) []byte {
	t.Helper()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty":        "OKP",
			"crv":        "Ed25519",
			"use":        "sig",
			"alg":        "EdDSA",
			"x":          base64.RawURLEncoding.EncodeToString(pub),
			"not_before": notBefore,
			"not_after":  notAfter,
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal wba doc: %v", err)
	}
	return raw
}

func wbaBody(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	return wbaBodyWindow(t, pub, "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z")
}

func TestResolve_FetchesActiveKeyAndCaches(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/http-message-signatures-directory" {
			http.NotFound(w, r)
			return
		}
		fetches.Add(1)
		_, _ = w.Write(wbaBody(t, pub))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := New(Config{Client: srv.Client(), Scheme: "http", Port: u.Port()})

	got, err := r.Resolve(context.Background(), u.Hostname())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("resolved key mismatch")
	}
	// Second resolve within TTL hits the cache — no second fetch.
	if _, err := r.Resolve(context.Background(), u.Hostname()); err != nil {
		t.Fatalf("cached resolve: %v", err)
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("directory fetched %d times; want 1 (TTL cache)", n)
	}
}

func TestResolve_ClampsCacheToKeyNotAfter(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	start := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	notAfter := start.Add(30 * time.Second)
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/http-message-signatures-directory" {
			http.NotFound(w, r)
			return
		}
		fetches.Add(1)
		_, _ = w.Write(wbaBodyWindow(t, pub, "2000-01-01T00:00:00Z", notAfter.Format(time.RFC3339)))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	clk := clock.NewDeterministic(start)
	// TTL far exceeds the key's remaining validity window, so the clamp — not
	// the TTL — must decide when the cache entry expires.
	r := New(Config{Client: srv.Client(), Scheme: "http", Port: u.Port(), TTL: time.Hour, Clk: clk})

	if _, err := r.Resolve(context.Background(), u.Hostname()); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	// Advance past not_after but far inside the raw TTL. Without the clamp the
	// cache would still serve the now-lapsed key; with it the entry has expired.
	clk.Advance(45 * time.Second)
	if _, err := r.Resolve(context.Background(), u.Hostname()); err == nil {
		t.Fatal("resolve after not_after must fail closed, not serve the lapsed key from cache")
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("directory fetched %d times; want 2 (entry expired at not_after, re-fetched)", n)
	}
}

// TestResolve_NilClientFailsClosed pins the Config.Client REQUIRED contract: a
// nil Client is never a fall-open to some in-package default — it surfaces
// rampwellknown.ErrNoClient the first time the resolver reaches for the
// directory. This keeps the docstring honest (the guarded client must be
// injected at the composition root; there is no fallback).
func TestResolve_NilClientFailsClosed(t *testing.T) {
	t.Parallel()
	r := New(Config{Scheme: "http"})
	_, err := r.Resolve(context.Background(), "exchange.example")
	if !errors.Is(err, rampwellknown.ErrNoClient) {
		t.Fatalf("want ErrNoClient when Client is omitted, got %v", err)
	}
}

func TestResolve_FailsClosedOnMissingDirectory(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := New(Config{Client: srv.Client(), Scheme: "http", Port: u.Port(), TTL: time.Minute})
	if _, err := r.Resolve(context.Background(), u.Hostname()); err == nil {
		t.Fatal("resolve against a keyless exchange must error (fail-closed)")
	}
}

package httpsig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

func TestStaticResolver_LookupAndPut(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	r := NewStaticResolver(map[string]ed25519.PublicKey{"k1": pub})
	got, err := r.Resolve(context.Background(), "k1")
	if err != nil {
		t.Fatalf("resolve k1: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("k1 pubkey mismatch")
	}

	_, err = r.Resolve(context.Background(), "missing")
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	r.Put("k2", pub2)
	got2, err := r.Resolve(context.Background(), "k2")
	if err != nil {
		t.Fatalf("resolve k2: %v", err)
	}
	if !got2.Equal(pub2) {
		t.Fatalf("k2 mismatch")
	}
}

func TestWellKnownResolver_FetchAndCache(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kid": "agent1.v1",
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   base64.RawURLEncoding.EncodeToString(pub),
					"use": "sig",
					"alg": "EdDSA",
				},
			},
		})
	}))
	t.Cleanup(srv.Close)

	clk := clock.NewDeterministic(time.Unix(1700000000, 0))
	r := NewWellKnownResolver(srv.URL, WellKnownOptions{
		TTL: 1 * time.Minute,
		Clk: clk,
	})
	got, err := r.Resolve(context.Background(), "agent1.v1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("pubkey mismatch")
	}
	if fetches != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", fetches)
	}
	// Cache hit — no new fetch.
	if _, err := r.Resolve(context.Background(), "agent1.v1"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if fetches != 1 {
		t.Fatalf("expected cached resolve, got %d fetches", fetches)
	}
	// Advance clock past TTL — refetch.
	clk.Advance(2 * time.Minute)
	if _, err := r.Resolve(context.Background(), "agent1.v1"); err != nil {
		t.Fatalf("post-ttl resolve: %v", err)
	}
	if fetches != 2 {
		t.Fatalf("expected refetch after TTL, got %d fetches", fetches)
	}
}

func TestWellKnownResolver_AllowlistRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatalf("allowlist rejection should short-circuit before fetch")
	}))
	t.Cleanup(srv.Close)

	r := NewWellKnownResolver(srv.URL, WellKnownOptions{
		Allow: func(keyID string) bool { return keyID == "allowed.v1" },
	})
	_, err := r.Resolve(context.Background(), "rogue.v1")
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

func TestWellKnownResolver_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	r := NewWellKnownResolver(srv.URL, WellKnownOptions{})
	_, err := r.Resolve(context.Background(), "any")
	if err == nil {
		t.Fatalf("want error on bad status")
	}
}

func TestWellKnownResolver_KeyRotation(t *testing.T) {
	// First JWKS answers with keyA; subsequent fetches swap to keyB. Simulates
	// a rotation pushed by the operator while the resolver is long-lived.
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		var active ed25519.PublicKey
		if calls == 1 {
			active = pubA
		} else {
			active = pubB
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kid": "rot.v1", "kty": "OKP", "crv": "Ed25519",
					"x": base64.RawURLEncoding.EncodeToString(active),
				},
			},
		})
	}))
	t.Cleanup(srv.Close)

	clk := clock.NewDeterministic(time.Unix(1700000000, 0))
	r := NewWellKnownResolver(srv.URL, WellKnownOptions{
		TTL: 10 * time.Second,
		Clk: clk,
	})

	gotA, err := r.Resolve(context.Background(), "rot.v1")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if !gotA.Equal(pubA) {
		t.Fatalf("expected pubA from first fetch")
	}
	// Advance past TTL so the second Resolve triggers a fresh fetch.
	clk.Advance(1 * time.Minute)
	gotB, err := r.Resolve(context.Background(), "rot.v1")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if !gotB.Equal(pubB) {
		t.Fatalf("expected pubB after rotation")
	}
}

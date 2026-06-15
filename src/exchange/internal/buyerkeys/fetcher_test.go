package buyerkeys_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/buyerkeys"
)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
}

func encodePub(p ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(p)
}

func newJWKSServer(t *testing.T, keys ...jwk) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestContainsHit(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newJWKSServer(t, jwk{Kty: "OKP", Crv: "Ed25519", X: encodePub(pub), Kid: "buyer-1"})
	f := buyerkeys.New(buyerkeys.Config{AllowInsecure: true})
	ok, err := f.Contains(context.Background(), srv.URL, pub)
	if err != nil {
		t.Fatalf("contains: %v", err)
	}
	if !ok {
		t.Fatal("want true")
	}
}

func TestContainsMiss(t *testing.T) {
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	stalePub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newJWKSServer(t, jwk{Kty: "OKP", Crv: "Ed25519", X: encodePub(other), Kid: "buyer-1"})
	f := buyerkeys.New(buyerkeys.Config{AllowInsecure: true})
	ok, err := f.Contains(context.Background(), srv.URL, stalePub)
	if err != nil {
		t.Fatalf("contains: %v", err)
	}
	if ok {
		t.Fatal("want false for stale key")
	}
}

func TestCacheTTL(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var fetchCount int32
	body := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + encodePub(pub) + `","kid":"buyer-1"}]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	frozen := time.Now()
	f := buyerkeys.New(buyerkeys.Config{
		AllowInsecure: true,
		Clk:           clock.NewDeterministic(frozen),
		TTL:           1 * time.Minute,
	})
	for range 3 {
		if _, err := f.Contains(context.Background(), srv.URL, pub); err != nil {
			t.Fatalf("contains: %v", err)
		}
	}
	if got := atomic.LoadInt32(&fetchCount); got != 1 {
		t.Fatalf("want 1 fetch, got %d", got)
	}
}

func TestFailClosedOnFirstFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	f := buyerkeys.New(buyerkeys.Config{AllowInsecure: true})
	_, err := f.Contains(context.Background(), srv.URL, pub)
	if !errors.Is(err, buyerkeys.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestHTTPRejectedUnlessAllowed(t *testing.T) {
	f := buyerkeys.New(buyerkeys.Config{})
	_, err := f.Contains(context.Background(), "http://example.invalid/", nil)
	if !errors.Is(err, buyerkeys.ErrInsecureScheme) {
		t.Fatalf("want ErrInsecureScheme, got %v", err)
	}
}

func TestServesStaleOnRefreshError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ok := true
	body := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + encodePub(pub) + `","kid":"buyer-1"}]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !ok {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	// First request populates the cache.
	frozen := time.Now()
	clk := clock.NewDeterministic(frozen)
	f := buyerkeys.New(buyerkeys.Config{
		AllowInsecure: true,
		Clk:           clk,
		TTL:           1 * time.Minute,
	})
	if _, err := f.Contains(context.Background(), srv.URL, pub); err != nil {
		t.Fatalf("first contains: %v", err)
	}
	// Clock jumps past TTL; upstream now failing.
	clk.Advance(2 * time.Minute)
	ok = false
	found, err := f.Contains(context.Background(), srv.URL, pub)
	if err != nil {
		t.Fatalf("stale contains: %v", err)
	}
	if !found {
		t.Fatalf("stale cache should keep serving on refresh failure")
	}
}

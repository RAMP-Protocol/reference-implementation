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

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/buyerkeys"
)

type jwk struct {
	Kty       string `json:"kty"`
	Crv       string `json:"crv"`
	X         string `json:"x"`
	Kid       string `json:"kid"`
	Use       string `json:"use,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

func encodePub(p ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(p)
}

// relaxEnv drops both SDK guards via the env flags, so a loopback httptest server
// (http://127.0.0.1) is reachable: SKIP_SSRF disables the dial-time address guard
// and ALLOW_INSECURE permits the plaintext http scheme. This is the sanctioned
// escape hatch now that the SDK owns scheme/address policy — the app carries no
// config-driven insecure toggle of its own.
func relaxEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SKIP_SSRF", "true")
	t.Setenv("ALLOW_INSECURE", "true")
}

// newFetcher constructs a Fetcher for the test. Production New no longer
// fabricates a fallback HTTP client, so the composition-root responsibility of
// building the SSRF-guarded client lives here: when a test leaves cfg.HTTP nil,
// the helper injects the same env-driven guarded client (5s budget) the
// composition root would, so existing tests keep their loopback-dial behavior
// under relaxEnv. Tests that need to prove the nil-client guard call
// buyerkeys.New directly, bypassing this helper.
func newFetcher(t *testing.T, cfg buyerkeys.Config) *buyerkeys.Fetcher {
	t.Helper()
	if cfg.HTTP == nil {
		guarded := resolvers.NewGuardedClientFromEnv()
		guarded.Timeout = 5 * time.Second
		cfg.HTTP = guarded
	}
	return buyerkeys.New(cfg)
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
	relaxEnv(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newJWKSServer(t, jwk{Kty: "OKP", Crv: "Ed25519", X: encodePub(pub), Kid: "buyer-1"})
	f := newFetcher(t, buyerkeys.Config{})
	ok, err := f.Contains(context.Background(), srv.URL, pub)
	if err != nil {
		t.Fatalf("contains: %v", err)
	}
	if !ok {
		t.Fatal("want true")
	}
}

// TestContainsSkipsMalformedEntry pins the fail-closed-SKIP contract buyerkeys
// inherits by routing its JWKS decode through the shared keypolicy.LoadJWKSBytes
// loader (the same loader the Broker key registry uses): a JWKS carrying one
// undecodable entry alongside a valid key still resolves the valid key — one
// typo in a buyer's key document cannot wedge the whole set. On the pre-shared
// implementation the undecodable `x` failed the entire parse (ErrMalformed →
// ErrUnavailable), so this is the observable behavior the migration introduces.
func TestContainsSkipsMalformedEntry(t *testing.T) {
	relaxEnv(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// First entry's x is not valid base64url → skipped by the shared loader;
	// the second, valid entry must still resolve.
	srv := newJWKSServer(t,
		jwk{Kty: "OKP", Crv: "Ed25519", X: "!!!not-base64!!!", Kid: "bad"},
		jwk{Kty: "OKP", Crv: "Ed25519", X: encodePub(pub), Kid: "buyer-1"},
	)
	f := newFetcher(t, buyerkeys.Config{})
	ok, err := f.Contains(context.Background(), srv.URL, pub)
	if err != nil {
		t.Fatalf("contains: %v", err)
	}
	if !ok {
		t.Fatal("valid key must resolve despite a sibling malformed entry")
	}
}

// TestContainsSkipsTypoedWindow drives the fail-closed window parse through
// the surface that reaches it in this service: a buyer key whose not_after is
// a typo must be SKIPPED by the shared decode, never treated as unbounded — a
// typo that widened validity would make the key permanently valid. The sibling
// valid key still resolves, proving the skip is per-entry.
func TestContainsSkipsTypoedWindow(t *testing.T) {
	relaxEnv(t)
	typoed, _, _ := ed25519.GenerateKey(rand.Reader)
	valid, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newJWKSServer(t,
		jwk{Kty: "OKP", Crv: "Ed25519", X: encodePub(typoed), Kid: "typo", NotAfter: "not-a-timestamp"},
		jwk{Kty: "OKP", Crv: "Ed25519", X: encodePub(valid), Kid: "buyer-1"},
	)
	f := newFetcher(t, buyerkeys.Config{})
	if ok, err := f.Contains(context.Background(), srv.URL, typoed); err != nil || ok {
		t.Fatalf("key with unparseable window resolved (ok=%v, err=%v); a typo must never widen validity", ok, err)
	}
	if ok, err := f.Contains(context.Background(), srv.URL, valid); err != nil || !ok {
		t.Fatalf("sibling valid key must still resolve (ok=%v, err=%v)", ok, err)
	}
}

// TestWindowEnforcedAtUseTime pins the property that a published validity
// window actually gates lookups, and does so at USE time against the fetcher's
// clock — not once at fetch time. A key can lapse while sitting in a warm
// cache; the moment now passes not_after, both lookup surfaces must stop
// returning it.
func TestWindowEnforcedAtUseTime(t *testing.T) {
	relaxEnv(t)
	frozen := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	clk := clock.NewDeterministic(frozen)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newJWKSServer(t, jwk{
		Kty: "OKP", Crv: "Ed25519", X: encodePub(pub), Kid: "buyer-1",
		NotBefore: frozen.Add(-time.Hour).Format(time.RFC3339),
		NotAfter:  frozen.Add(time.Hour).Format(time.RFC3339),
	})
	// TTL longer than the clock jump below, so the lapsed-key lookups hit the
	// WARM cache. That is the point of the test: with the default 5-minute TTL
	// the +62m lookup would refetch, and a window check that ran only at fetch
	// time would pass here while failing in production between refreshes.
	f := newFetcher(t, buyerkeys.Config{Clk: clk, TTL: 2 * time.Hour})

	if ok, err := f.Contains(context.Background(), srv.URL, pub); err != nil || !ok {
		t.Fatalf("in-window key must resolve (ok=%v, err=%v)", ok, err)
	}
	if _, ok, err := f.LookupKID(context.Background(), srv.URL, "buyer-1"); err != nil || !ok {
		t.Fatalf("in-window kid must resolve (ok=%v, err=%v)", ok, err)
	}

	// Two minutes past not_after: the cache still holds the entry (2h TTL) —
	// the verdict must flip anyway.
	clk.SetNow(frozen.Add(time.Hour + 2*time.Minute))
	if ok, err := f.Contains(context.Background(), srv.URL, pub); err != nil || ok {
		t.Fatalf("lapsed key resolved (ok=%v, err=%v); the window must gate use, not just fetch", ok, err)
	}
	if _, ok, err := f.LookupKID(context.Background(), srv.URL, "buyer-1"); err != nil || ok {
		t.Fatalf("lapsed kid resolved (ok=%v, err=%v)", ok, err)
	}
}

// TestDuplicateEntriesDocumentOrderIrrelevant pins Contains against document
// order: a JWKS may list the same public key twice (a kid rename
// mid-rotation), and a lapsed duplicate listed FIRST must not hide the
// currently valid entry behind it. A loop that returned the first byte-equal
// entry's window verdict would answer false here.
func TestDuplicateEntriesDocumentOrderIrrelevant(t *testing.T) {
	relaxEnv(t)
	frozen := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	clk := clock.NewDeterministic(frozen)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newJWKSServer(t,
		jwk{
			Kty: "OKP", Crv: "Ed25519", X: encodePub(pub), Kid: "buyer-1.old",
			NotBefore: frozen.Add(-2 * time.Hour).Format(time.RFC3339),
			NotAfter:  frozen.Add(-time.Hour).Format(time.RFC3339),
		},
		jwk{
			Kty: "OKP", Crv: "Ed25519", X: encodePub(pub), Kid: "buyer-1.new",
			NotBefore: frozen.Add(-time.Hour).Format(time.RFC3339),
			NotAfter:  frozen.Add(time.Hour).Format(time.RFC3339),
		},
	)
	f := newFetcher(t, buyerkeys.Config{Clk: clk})
	if ok, err := f.Contains(context.Background(), srv.URL, pub); err != nil || !ok {
		t.Fatalf("valid key hidden behind a lapsed duplicate (ok=%v, err=%v)", ok, err)
	}
}

// TestNotYetValidKeyIsRejected covers the other window edge: a key published
// ahead of its not_before must not resolve until the bound passes.
func TestNotYetValidKeyIsRejected(t *testing.T) {
	relaxEnv(t)
	frozen := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	clk := clock.NewDeterministic(frozen)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newJWKSServer(t, jwk{
		Kty: "OKP", Crv: "Ed25519", X: encodePub(pub), Kid: "buyer-1",
		NotBefore: frozen.Add(time.Hour).Format(time.RFC3339),
	})
	f := newFetcher(t, buyerkeys.Config{Clk: clk})
	if ok, err := f.Contains(context.Background(), srv.URL, pub); err != nil || ok {
		t.Fatalf("not-yet-valid key resolved (ok=%v, err=%v)", ok, err)
	}
	clk.SetNow(frozen.Add(2 * time.Hour))
	if ok, err := f.Contains(context.Background(), srv.URL, pub); err != nil || !ok {
		t.Fatalf("key must resolve once not_before passes (ok=%v, err=%v)", ok, err)
	}
}

func TestContainsMiss(t *testing.T) {
	relaxEnv(t)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	stalePub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := newJWKSServer(t, jwk{Kty: "OKP", Crv: "Ed25519", X: encodePub(other), Kid: "buyer-1"})
	f := newFetcher(t, buyerkeys.Config{})
	ok, err := f.Contains(context.Background(), srv.URL, stalePub)
	if err != nil {
		t.Fatalf("contains: %v", err)
	}
	if ok {
		t.Fatal("want false for stale key")
	}
}

func TestCacheTTL(t *testing.T) {
	relaxEnv(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var fetchCount int32
	body := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + encodePub(pub) + `","kid":"buyer-1"}]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	frozen := time.Now()
	f := newFetcher(t, buyerkeys.Config{
		Clk: clock.NewDeterministic(frozen),
		TTL: 1 * time.Minute,
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
	relaxEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	f := newFetcher(t, buyerkeys.Config{})
	_, err := f.Contains(context.Background(), srv.URL, pub)
	if !errors.Is(err, buyerkeys.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

// TestHTTPRejectedInSecureMode pins that the SDK guard — not any app-side scheme
// gate — refuses a plaintext http:// URL when ALLOW_INSECURE is NOT granted.
// The blocked scheme surfaces as a fail-closed ErrUnavailable (no cached entry),
// so a buyer key hosted over http is never trusted in production.
func TestHTTPRejectedInSecureMode(t *testing.T) {
	// Secure mode: both flags explicitly OFF, so the SDK scheme guard blocks http
	// (https-only) before any dial.
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "")
	f := newFetcher(t, buyerkeys.Config{})
	_, err := f.Contains(context.Background(), "http://example.invalid/", nil)
	if !errors.Is(err, buyerkeys.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable (http blocked by the SDK guard), got %v", err)
	}
}

// TestZeroClientFailsLoudNotTransient pins the zero-client-fails-loud contract: a Fetcher
// constructed with NO injected HTTP client must fail LOUD with a PERMANENT
// configuration error — it must never silently fabricate a guarded client of
// its own, and it must never surface the missing-client condition as the
// TRANSIENT ErrUnavailable (the fail-closed / stale-serve kind).
//
// buyerkeys.New is the last sibling fetcher still fabricating an in-constructor
// guarded fallback; every peer (agentreg, probe, rampwellknown) requires the
// SSRF-guarded client as an injected dependency built once at the composition
// root. A missing client is a programmer misconfiguration, not a retryable
// upstream outage — so the guard must sit at construction (or at the top of
// resolve, BEFORE the ErrUnavailable reclassification), NOT at the top of
// fetch, where resolve would %w-chain it into ErrUnavailable and mask a hard
// config error as transient.
//
// Red-at-HEAD: New(Config{}) currently fabricates resolvers.NewGuardedClientFromEnv,
// so with SKIP_SSRF/ALLOW_INSECURE relaxed it dials the loopback JWKS server and
// resolves successfully (err == nil, one dial observed) — exactly the silent
// fabrication this test forbids.
func TestZeroClientFailsLoudNotTransient(t *testing.T) {
	relaxEnv(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var dials int32
	body := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + encodePub(pub) + `","kid":"buyer-1"}]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&dials, 1)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	// Construct with NO injected HTTP client, bypassing newFetcher on purpose:
	// newFetcher injects a guarded client when the caller leaves cfg.HTTP nil,
	// so routing through it here would make the assertion vacuous. New(Config{})
	// with a nil client must refuse on its own.
	f := buyerkeys.New(buyerkeys.Config{})

	_, err := f.Contains(context.Background(), srv.URL, pub)

	if err == nil {
		t.Fatal("want a loud config error for a nil HTTP client, got nil (client was silently fabricated)")
	}
	if errors.Is(err, buyerkeys.ErrUnavailable) {
		t.Fatalf("a missing client must surface as a PERMANENT config error, not the transient ErrUnavailable, got %v", err)
	}
	if got := atomic.LoadInt32(&dials); got != 0 {
		t.Fatalf("a fetcher with no injected client must not dial; observed %d dial(s) (client was fabricated)", got)
	}
}

func TestServesStaleOnRefreshError(t *testing.T) {
	relaxEnv(t)
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
	f := newFetcher(t, buyerkeys.Config{
		Clk: clk,
		TTL: 1 * time.Minute,
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

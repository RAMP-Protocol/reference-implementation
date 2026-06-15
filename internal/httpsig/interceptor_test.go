package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// newTestSignedRequest builds a signed request targeted at /ramp.v1/... so
// the default predicate picks it up.
func newTestSignedRequest(t *testing.T, url, body, authz string, priv ed25519.PrivateKey, now time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Authorization", authz)
	created := now.Unix()
	expires := now.Add(30 * time.Second).Unix()
	if err := SignRequestRAMP(req, []byte(body), testKeyID, priv, created, expires); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

func TestMiddleware_AcceptsSigned(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	replay := NewMemoryReplayStore(func() time.Time { return now })

	var seenKeyID string
	h := Middleware(resolver, replay, InterceptorOptions{
		Clk: clock.NewDeterministic(now),
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := FromContext(r.Context()); v != nil {
			seenKeyID = v.KeyID
		}
		// Ensure downstream still gets the body.
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	bodyStr := `{"q":"x"}`
	req := newTestSignedRequest(t, srv.URL+"/ramp.v1.ExchangeService/DiscoverResources", bodyStr, "Bearer jwt", priv, now)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != bodyStr {
		t.Fatalf("handler body = %q, want %q", got, bodyStr)
	}
	if seenKeyID != testKeyID {
		t.Fatalf("handler saw keyid %q, want %q", seenKeyID, testKeyID)
	}
}

func TestMiddleware_RejectsUnsignedWith401(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	replay := NewMemoryReplayStore(func() time.Time { return now })

	calls := 0
	h := Middleware(resolver, replay, InterceptorOptions{
		Clk: clock.NewDeterministic(now),
	}, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { calls++ }))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader([]byte(`{}`)))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if calls != 0 {
		t.Fatalf("handler should not have been called on rejected request")
	}
}

func TestMiddleware_RejectsReplay(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	replay := NewMemoryReplayStore(func() time.Time { return now })

	h := Middleware(resolver, replay, InterceptorOptions{
		Clk: clock.NewDeterministic(now),
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	bodyStr := `{"q":"x"}`
	req := newTestSignedRequest(t, srv.URL+"/ramp.v1.ExchangeService/DiscoverResources", bodyStr, "Bearer jwt", priv, now)
	// First request: capture headers to replay exactly.
	first := req.Clone(req.Context())
	first.Body = io.NopCloser(bytes.NewReader([]byte(bodyStr)))
	resp, err := srv.Client().Do(first)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", resp.StatusCode)
	}
	// Second request: same keyid + same signature = replay.
	second := req.Clone(req.Context())
	second.Body = io.NopCloser(bytes.NewReader([]byte(bodyStr)))
	resp2, err := srv.Client().Do(second)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", resp2.StatusCode)
	}
}

func TestMiddleware_SkipsNonRampPaths(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	replay := NewMemoryReplayStore(func() time.Time { return now })

	called := false
	h := Middleware(resolver, replay, InterceptorOptions{
		Clk: clock.NewDeterministic(now),
	}, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/healthz", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if !called {
		t.Fatalf("/healthz should have passed through without signature")
	}
}

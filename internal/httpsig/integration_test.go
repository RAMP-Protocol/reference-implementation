//go:build integration

package httpsig_test

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

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

func signRAMPCall(tb testing.TB, target, bodyStr, authz string, priv ed25519.PrivateKey) *http.Request {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, bytes.NewReader([]byte(bodyStr)))
	if err != nil {
		tb.Fatalf("new req: %v", err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Authorization", authz)
	created := time.Now().Unix()
	expires := created + 30
	// After the WBA split the RFC 9421 keyid is the key's RFC 7638 thumbprint.
	keyid, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		tb.Fatalf("thumbprint: %v", err)
	}
	if err := httpsig.SignRequestRAMP(req, []byte(bodyStr), keyid, priv, expires); err != nil {
		tb.Fatalf("sign: %v", err)
	}
	return req
}

// TestIntegration_ExchangeRejectsUnsigned sets up a tiny Connect-like mux
// wrapped in the httpsig middleware and confirms:
//  1. Unsigned → 401.
//  2. Signed with a registered key → 200.
//  3. Replay of the same (keyID, signature) within the window → 401.
func TestIntegration_ExchangeRejectsUnsigned(t *testing.T) {
	ctx := context.Background()
	redisCli := testutil.StartRedis(t, ctx)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	tp, tperr := helpers.Thumbprint(pub)
	if tperr != nil {
		t.Fatalf("thumbprint: %v", tperr)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{tp: pub})
	replay := httpsig.NewRedisReplayStore(redisCli, "httpsig:integ:replay:")

	handler := httpsig.Middleware(resolver, replay, httpsig.InterceptorOptions{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// 1. Unsigned request to a /ramp.v1.* path.
	unsigned, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.URL+"/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	resp1, err := srv.Client().Do(unsigned)
	if err != nil {
		t.Fatalf("unsigned do: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d, want 401", resp1.StatusCode)
	}

	// 2. Valid signed request.
	bodyStr := `{"q":"x"}`
	target := srv.URL + "/ramp.v1.ExchangeService/DiscoverResources"
	req2 := signRAMPCall(t, target, bodyStr, "Bearer jwt-token", priv)
	resp2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatalf("signed do: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("signed status = %d, want 200", resp2.StatusCode)
	}

	// 3. Replay the same headers + body → 401.
	req3 := signRAMPCall(t, target, bodyStr, "Bearer jwt-token", priv)
	// Force identical Signature bytes by re-using req2's headers (the clock may have ticked).
	req3.Header = req2.Header.Clone()
	req3.Body = io.NopCloser(bytes.NewReader([]byte(bodyStr)))
	req3.ContentLength = int64(len(bodyStr))
	resp3, err := srv.Client().Do(req3)
	if err != nil {
		t.Fatalf("replay do: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", resp3.StatusCode)
	}
}

// TestIntegration_RedisReplayTTL asserts that after the TTL expires, a
// second submit with the same keyID+signature is treated as fresh. The
// Redis-backed store relies on SETNX+EX, so this is a contract test for the
// round-trip through the real Redis server.
func TestIntegration_RedisReplayTTL(t *testing.T) {
	ctx := context.Background()
	redisCli := testutil.StartRedis(t, ctx)
	replay := httpsig.NewRedisReplayStore(redisCli, "httpsig:integ:replay:")

	seen, err := replay.SeenOrAdd(ctx, "agent-1", "sig-abc", 1*time.Second)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if seen {
		t.Fatalf("first SeenOrAdd returned seen=true")
	}
	// Second call within TTL must report seen=true.
	seen2, err := replay.SeenOrAdd(ctx, "agent-1", "sig-abc", 1*time.Second)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !seen2 {
		t.Fatalf("second SeenOrAdd returned seen=false, want true")
	}

	// Let the TTL expire.
	time.Sleep(1500 * time.Millisecond)
	seen3, err := replay.SeenOrAdd(ctx, "agent-1", "sig-abc", 1*time.Second)
	if err != nil {
		t.Fatalf("third: %v", err)
	}
	if seen3 {
		t.Fatalf("third SeenOrAdd after TTL returned seen=true, want false")
	}
}

package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
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
	expires := now.Add(30 * time.Second).Unix()
	if err := SignRequestRAMP(req, []byte(body), testKeyID, priv, expires); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

func TestMiddleware_AcceptsSigned(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := signNow()
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
	now := signNow()
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
	now := signNow()
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

// TestMiddleware_MultisigReplayDoesNotBurnOtherSignatures pins the multisig replay contract: when a
// multisig request is rejected because ONE of its signatures is a replay, the
// OTHER (valid, first-seen) signatures must not be recorded — otherwise an
// attacker could pre-burn an agent's signature by pairing it with a replayed
// broker signature, denying the agent's legitimate request.
func TestMiddleware_MultisigReplayDoesNotBurnOtherSignatures(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pub1: %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pub2: %v", err)
	}
	now := signNow()
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{"key1": pub1, "key2": pub2})
	replay := NewMemoryReplayStore(func() time.Time { return now })

	bodyStr := `{"q":"x"}`
	build := func() *http.Request {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"http://example.test/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader([]byte(bodyStr)))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Host = req.URL.Host
		req.Header.Set("Authorization", "Bearer jwt")
		expires := now.Add(30 * time.Second).Unix()
		if err := SignRequestRAMP(req, []byte(bodyStr), "key1", priv1, expires); err != nil {
			t.Fatalf("sign 1: %v", err)
		}
		if err := AppendSignatureRAMP(req, []byte(bodyStr), "key2", priv2, expires); err != nil {
			t.Fatalf("sign 2: %v", err)
		}
		return req
	}

	// Build and sign the multisig request ONCE; clone it for the verify leg so the
	// seeded sig2 and the verified sig2 are identical by construction. yaronf
	// stamps created = time.Now() per sign call, so re-signing via a second build()
	// would desync the bytes across a wall-clock second boundary and silently miss
	// the replay (regression-guard flake).
	req := build()

	// Recover the per-label replay keys (keyID, base64 signature) from the request.
	_, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	agentSig := base64.StdEncoding.EncodeToString(sigMap["sig1"])
	brokerSig := base64.StdEncoding.EncodeToString(sigMap["sig2"])

	// Pre-seed ONLY the broker (sig2) key, so the request replays on its second
	// label while its first (agent) label is first-seen.
	if _, err := replay.SeenOrAdd(context.Background(), "key2", brokerSig, 30*time.Second); err != nil {
		t.Fatalf("seed: %v", err)
	}

	c := middlewareConfig{
		ttl:        30 * time.Second,
		verifyOpts: VerifyRequestOptions{Clk: clock.NewDeterministic(now)},
	}
	verifyReq := req.Clone(req.Context())
	verifyReq.Body = io.NopCloser(bytes.NewReader([]byte(bodyStr)))
	if _, err := c.verifyMultisig(verifyReq, resolver, replay); !errors.Is(err, ErrReplayed) {
		t.Fatalf("verifyMultisig err = %v, want ErrReplayed", err)
	}

	// The agent's (sig1) replay key MUST remain unburned.
	if seen, _ := replay.Seen(context.Background(), "key1", agentSig); seen {
		t.Fatal("agent signature was burned by a rejected multisig request")
	}
}

func TestMiddleware_SkipsNonRampPaths(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := signNow()
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

func TestMiddleware_MultisigStoresAllSignatures(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pub1: %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pub2: %v", err)
	}
	now := signNow()
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
		"key1": pub1,
		"key2": pub2,
	})
	replay := NewMemoryReplayStore(func() time.Time { return now })

	var seenSigs []VerifiedRequest
	h := Middleware(resolver, replay, InterceptorOptions{
		Clk: clock.NewDeterministic(now),
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenSigs = AllSignaturesFromContext(r.Context())
		// Verify FromContext backward compat returns first sig
		if v := FromContext(r.Context()); v != nil && len(seenSigs) > 0 {
			if v.KeyID != seenSigs[0].KeyID {
				t.Errorf("FromContext keyID = %q, want %q", v.KeyID, seenSigs[0].KeyID)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	bodyStr := `{"q":"x"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader([]byte(bodyStr)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Authorization", "Bearer jwt")

	// Sign with first key
	expires := now.Add(30 * time.Second).Unix()
	if err := SignRequestRAMP(req, []byte(bodyStr), "key1", priv1, expires); err != nil {
		t.Fatalf("sign 1: %v", err)
	}

	// Append second signature
	if err := AppendSignatureRAMP(req, []byte(bodyStr), "key2", priv2, expires); err != nil {
		t.Fatalf("sign 2: %v", err)
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(seenSigs) != 2 {
		t.Fatalf("handler saw %d sigs, want 2", len(seenSigs))
	}
	if seenSigs[0].KeyID != "key1" {
		t.Errorf("sig[0].KeyID = %q, want key1", seenSigs[0].KeyID)
	}
	if seenSigs[1].KeyID != "key2" {
		t.Errorf("sig[1].KeyID = %q, want key2", seenSigs[1].KeyID)
	}
}

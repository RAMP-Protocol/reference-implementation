package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

const testKeyID = "agent-demo.v1"

func newRAMPSignedRequest(t *testing.T, body []byte, priv ed25519.PrivateKey, now time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "exchange.example"
	req.Header.Set("Authorization", "Bearer test-jwt")
	created := now.Unix()
	expires := now.Add(30 * time.Second).Unix()
	if err := SignRequestRAMP(req, body, testKeyID, priv, created, expires); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

func TestVerifyRequest_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"foo"}`)
	req := newRAMPSignedRequest(t, body, priv, now)

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	v, err := VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.KeyID != testKeyID {
		t.Fatalf("keyid = %q, want %q", v.KeyID, testKeyID)
	}
	if v.Expires == 0 {
		t.Fatalf("expires not captured")
	}
}

func TestVerifyRequest_Unsigned(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	_ = priv
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver)
	if !errors.Is(err, ErrMissingSignatureInput) {
		t.Fatalf("want ErrMissingSignatureInput, got %v", err)
	}
}

func TestVerifyRequest_BadSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"hello":"world"}`)
	req := newRAMPSignedRequest(t, body, priv, now)

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: wrongPub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify, got %v", err)
	}
}

func TestVerifyRequest_MissingCoverageComponent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "exchange.example"
	// Use the legacy short-coverage signer — it omits @target-uri and
	// authorization, which RAMP policy requires.
	if err := SignRequest(req, body, testKeyID, priv, 1700000000); err != nil {
		t.Fatalf("sign: %v", err)
	}
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(time.Unix(1700000000, 0))})
	if !errors.Is(err, ErrMissingRequiredComponent) {
		t.Fatalf("want ErrMissingRequiredComponent, got %v", err)
	}
}

func TestVerifyRequest_Expired(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"hello":"world"}`)
	req := newRAMPSignedRequest(t, body, priv, now)

	future := now.Add(5 * time.Minute)
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(future)})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestVerifyRequest_FutureCreatedRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	// Sign with a 'created' that is > 300s ahead of the verifier clock.
	signerNow := time.Unix(1700000000, 0)
	body := []byte(`{"hello":"world"}`)
	req := newRAMPSignedRequest(t, body, priv, signerNow)

	behind := signerNow.Add(-10 * time.Minute)
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(behind)})
	if !errors.Is(err, ErrFutureCreated) {
		t.Fatalf("want ErrFutureCreated, got %v", err)
	}
}

func TestVerifyRequest_TamperedAuthorizationRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"hello":"world"}`)
	req := newRAMPSignedRequest(t, body, priv, now)
	req.Header.Set("Authorization", "Bearer tampered")

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify, got %v", err)
	}
}

func TestReadAndRestoreBody_IdempotentRead(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example/", bytes.NewReader(body))
	got, err := readAndRestoreBody(req)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q, want %q", got, body)
	}
	// Subsequent reader must still deliver the same bytes.
	var again bytes.Buffer
	if _, err := again.ReadFrom(req.Body); err != nil {
		t.Fatalf("reread: %v", err)
	}
	if again.String() != string(body) {
		t.Fatalf("restored body = %q, want %q", again.String(), body)
	}
}

func TestVerifyRequest_EntitlementHeaderCovered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"q":"x"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "exchange.example"
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("X-RAMP-Entitlement-Biscuit", "AAAA")
	if err := SignRequestRAMP(req, body, testKeyID, priv, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Signer MUST have added the header to coverage.
	inp := req.Header.Get("Signature-Input")
	if !strings.Contains(inp, `"x-ramp-entitlement-biscuit"`) {
		t.Fatalf("signer did not cover entitlement header: %s", inp)
	}
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	if _, err := VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRequest_EntitlementHeaderPresentButUncovered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"q":"x"}`)
	// Sign WITHOUT the biscuit header set.
	req := newRAMPSignedRequest(t, body, priv, now)
	// Smuggle the biscuit header in after signing — the verifier must
	// reject because coverage does not include it.
	req.Header.Set("X-RAMP-Entitlement-Biscuit", "AAAA")

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrMissingRequiredComponent) {
		t.Fatalf("want ErrMissingRequiredComponent, got %v", err)
	}
}

func TestVerifyRequest_TamperedEntitlementHeaderRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"q":"x"}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	req.Host = "exchange.example"
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("X-RAMP-Entitlement-Biscuit", "ORIGINAL")
	if err := SignRequestRAMP(req, body, testKeyID, priv, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Swap the biscuit after signing.
	req.Header.Set("X-RAMP-Entitlement-Biscuit", "TAMPERED")

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify, got %v", err)
	}
}

func TestVerifyRequest_UnknownKeyid(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"q":"x"}`)
	req := newRAMPSignedRequest(t, body, priv, now)

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

func TestVerifyRequest_BadAlgRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{}`)
	req := newRAMPSignedRequest(t, body, priv, now)
	// Re-write alg in Signature-Input to a rejected algorithm.
	inp := req.Header.Get("Signature-Input")
	req.Header.Set("Signature-Input", strings.Replace(inp, `alg="ed25519"`, `alg="rsa-pss-sha256"`, 1))

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("want ErrUnsupportedAlgorithm, got %v", err)
	}
}

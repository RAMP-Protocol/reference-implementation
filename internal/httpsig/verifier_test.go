package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

const testKeyID = "agent-demo.v1"

// newRAMPSignedRequest signs body under testKeyID with the standard now+30s
// expiry. It delegates to newRAMPSignedRequestExpiring (chain_test.go), the single
// definition of "a RAMP-signed request", so the request shape lives in one place.
func newRAMPSignedRequest(t *testing.T, body []byte, priv ed25519.PrivateKey, now time.Time) *http.Request {
	t.Helper()
	return newRAMPSignedRequestExpiring(t, body, priv, now.Add(30*time.Second).Unix())
}

func TestVerifyRequest_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := signNow()
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
	now := signNow()
	body := []byte(`{"hello":"world"}`)
	req := newRAMPSignedRequest(t, body, priv, now)

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: wrongPub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify, got %v", err)
	}
	// The sentinel must WRAP the underlying cause, not collapse to it bare
	// — a future regression to `return ErrSignatureVerify` would drop the
	// yaronf cause and fail this guard. Assert augmentation, not exact wording.
	if err.Error() == ErrSignatureVerify.Error() {
		t.Fatalf("cause discarded: error is the bare sentinel %q", err)
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
	now := signNow()
	// Sign with a deliberately short coverage set — it omits @target-uri and
	// authorization, which RAMP policy requires — to drive the required-component
	// check, which runs before the time window.
	shortCoverage := Params{
		Label:   "sig1",
		Covered: plainComponents("@method", "@path", "@authority", "content-digest"),
		KeyID:   testKeyID,
		Alg:     "ed25519",
	}
	setContentDigest(req, body)
	if err := signWithParams(req, shortCoverage, priv, sigWriteSet); err != nil {
		t.Fatalf("sign: %v", err)
	}
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrMissingRequiredComponent) {
		t.Fatalf("want ErrMissingRequiredComponent, got %v", err)
	}
}

func TestVerifyRequest_Expired(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := signNow()
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
	// The signer stamps created = now() (yaronf). Put the verifier clock 10
	// minutes BEHIND now so created is > 300s in the verifier's future.
	signerNow := signNow()
	body := []byte(`{"hello":"world"}`)
	req := newRAMPSignedRequest(t, body, priv, signerNow)

	behind := signerNow.Add(-10 * time.Minute)
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(behind)})
	if !errors.Is(err, ErrFutureCreated) {
		t.Fatalf("want ErrFutureCreated, got %v", err)
	}
}

func TestVerifyRequest_MissingCreatedRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := signNow()
	body := []byte(`{"q":"x"}`)
	req := newRAMPSignedRequest(t, body, priv, now)
	// Strip created= from Signature-Input so the parsed Params.Created is 0.
	// enforceCreatedExpires rejects with ErrMissingCreated before the Ed25519
	// check, so the signature the mutation invalidated is never reached. Pattern
	// strip (not value) because yaronf stamps created = real now() at sign time.
	inp := req.Header.Get("Signature-Input")
	req.Header.Set("Signature-Input", regexp.MustCompile(`;created=\d+`).ReplaceAllString(inp, ""))

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrMissingCreated) {
		t.Fatalf("want ErrMissingCreated, got %v", err)
	}
}

func TestVerifyRequest_MissingExpiresRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := signNow()
	body := []byte(`{"q":"x"}`)
	req := newRAMPSignedRequest(t, body, priv, now)
	// Strip expires= so the parsed Params.Expires is 0 → ErrMissingExpires, which
	// also fires before the Ed25519 check.
	inp := req.Header.Get("Signature-Input")
	req.Header.Set("Signature-Input", regexp.MustCompile(`;expires=\d+`).ReplaceAllString(inp, ""))

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrMissingExpires) {
		t.Fatalf("want ErrMissingExpires, got %v", err)
	}
}

func TestVerifyRequest_TamperedAuthorizationRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := signNow()
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
	now := signNow()
	body := []byte(`{"q":"x"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "exchange.example"
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("X-RAMP-Entitlement-Biscuit", "AAAA")
	if err := SignRequestRAMP(req, body, testKeyID, priv, now.Add(30*time.Second).Unix()); err != nil {
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
	now := signNow()
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
	now := signNow()
	body := []byte(`{"q":"x"}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	req.Host = "exchange.example"
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("X-RAMP-Entitlement-Biscuit", "ORIGINAL")
	if err := SignRequestRAMP(req, body, testKeyID, priv, now.Add(30*time.Second).Unix()); err != nil {
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
	now := signNow()
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
	now := signNow()
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

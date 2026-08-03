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

// TestAppendSignatureRAMP_EmptyHeaders verifies appending to a request with no
// existing signatures behaves like SignRequestRAMP.
func TestAppendSignatureRAMP_EmptyHeaders(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://broker.example/ramp.v1.BrokerService/Resolve", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "broker.example"
	req.Header.Set("Authorization", "Bearer token123")

	// yaronf stamps created = now(); sign at real now and verify under a
	// deterministic clock anchored at the same instant.
	now := signNow()
	expires := now.Add(100 * time.Second).Unix()
	err = AppendSignatureRAMP(req, body, "agent.test", priv, expires)
	if err != nil {
		t.Fatalf("AppendSignatureRAMP: %v", err)
	}

	// Verify the signature was added as sig1.
	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "sig1=") {
		t.Fatalf("want Signature-Input starting with sig1=, got %q", sigInput)
	}

	sig := req.Header.Get("Signature")
	if !strings.HasPrefix(sig, "sig1=") {
		t.Fatalf("want Signature starting with sig1=, got %q", sig)
	}

	// Verify the signature validates under the canonical verifier.
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{"agent.test": pub})
	v, err := VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if v.KeyID != "agent.test" {
		t.Fatalf("want keyid agent.test, got %q", v.KeyID)
	}
	if v.Label != "sig1" {
		t.Fatalf("want label sig1, got %q", v.Label)
	}
}

// TestAppendSignatureRAMP_MalformedSignatureInputRejected verifies the relay
// append path fails fast when an existing Signature-Input header is present but
// unparseable: rather than treating the garbage as "no signatures" and
// co-signing a fresh sig1 over a malformed envelope, AppendSignatureRAMP returns
// an ErrMalformedSignatureInput-wrapped error and does not append a signature.
func TestAppendSignatureRAMP_MalformedSignatureInputRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://broker.example/ramp.v1.BrokerService/Resolve", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "broker.example"
	req.Header.Set("Authorization", "Bearer token123")

	// A Signature-Input that is present but not a valid structured-field
	// dictionary, with a matching Signature header so the envelope is genuinely
	// "signed but malformed" rather than absent.
	const malformedInput = "sig1=(((garbage"
	const existingSig = "sig1=:AAAA:"
	req.Header.Set("Signature-Input", malformedInput)
	req.Header.Set("Signature", existingSig)

	now := signNow()
	err = AppendSignatureRAMP(req, body, "broker.test", priv, now.Add(30*time.Second).Unix())
	if !errors.Is(err, ErrMalformedSignatureInput) {
		t.Fatalf("want ErrMalformedSignatureInput, got %v", err)
	}

	// No co-signing side effect: the existing Signature/Signature-Input headers
	// are untouched — no fresh sigN was appended over the malformed envelope.
	if got := req.Header.Get("Signature-Input"); got != malformedInput {
		t.Fatalf("Signature-Input mutated: want %q, got %q", malformedInput, got)
	}
	if got := req.Header.Get("Signature"); got != existingSig {
		t.Fatalf("Signature mutated: want %q, got %q", existingSig, got)
	}
}

// verifySignatureAtIndex is a helper that verifies a signature at a specific
// index in the params list. It drives the production yaronf-backed verify
// (verifyEd25519) so the test exercises the real canonicalization rather than a
// hand-rolled base. body is restored inside verifyEd25519 for the next label.
func verifySignatureAtIndex(
	t *testing.T, req *http.Request,
	allParams []Params, body []byte,
	idx int, wantLabel, wantKeyID string, pub ed25519.PublicKey,
) {
	t.Helper()
	if idx >= len(allParams) {
		t.Fatalf("index %d out of range (have %d params)", idx, len(allParams))
	}
	params := allParams[idx]
	if params.Label != wantLabel {
		t.Fatalf("params[%d]: want label %s, got %s", idx, wantLabel, params.Label)
	}
	if params.KeyID != wantKeyID {
		t.Fatalf("params[%d]: want keyid %s, got %s", idx, wantKeyID, params.KeyID)
	}
	if err := verifyEd25519(req, params.Label, pub, body); err != nil {
		t.Fatalf("%s verification failed: %v", wantLabel, err)
	}
}

// TestAppendSignatureRAMP_ExistingSig1 verifies appending when sig1 already
// exists creates sig2.
func TestAppendSignatureRAMP_ExistingSig1(t *testing.T) {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen agent: %v", err)
	}
	brokerPub, brokerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen broker: %v", err)
	}

	body := []byte(`{"url":"https://publisher.example/content"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://broker.example/ramp.v1.BrokerService/Resolve", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "broker.example"
	req.Header.Set("Authorization", "Bearer agent-token")

	// Agent signs first (creates sig1).
	expires := int64(1700000100)
	err = SignRequestRAMP(req, body, "agent.test", agentPriv, expires)
	if err != nil {
		t.Fatalf("SignRequestRAMP (agent): %v", err)
	}

	// Broker appends signature (should create sig2).
	err = AppendSignatureRAMP(req, body, "broker.test", brokerPriv, expires+1)
	if err != nil {
		t.Fatalf("AppendSignatureRAMP (broker): %v", err)
	}

	// Verify both signatures exist.
	sigInput := req.Header.Get("Signature-Input")
	if !strings.Contains(sigInput, "sig1=") {
		t.Fatalf("Signature-Input missing sig1: %q", sigInput)
	}
	if !strings.Contains(sigInput, "sig2=") {
		t.Fatalf("Signature-Input missing sig2: %q", sigInput)
	}

	// Parse and verify both signatures.
	allParams, _, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parseAllSignatures: %v", err)
	}
	if len(allParams) != 2 {
		t.Fatalf("want 2 signatures, got %d", len(allParams))
	}

	verifySignatureAtIndex(t, req, allParams, body, 0, "sig1", "agent.test", agentPub)
	verifySignatureAtIndex(t, req, allParams, body, 1, "sig2", "broker.test", brokerPub)
}

// TestAppendSignatureRAMP_TwiceAppends verifies calling AppendSignatureRAMP
// twice creates sig2, then sig3.
func TestAppendSignatureRAMP_TwiceAppends(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen 1: %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen 2: %v", err)
	}
	pub3, priv3, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen 3: %v", err)
	}

	body := []byte(`{"relay":"chain"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/CreateOffer", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "exchange.example"
	req.Header.Set("Authorization", "")

	expires := int64(1700000100)

	// First signature.
	err = SignRequestRAMP(req, body, "signer1.test", priv1, expires)
	if err != nil {
		t.Fatalf("SignRequestRAMP: %v", err)
	}

	// Append second signature.
	err = AppendSignatureRAMP(req, body, "signer2.test", priv2, expires+1)
	if err != nil {
		t.Fatalf("AppendSignatureRAMP (second): %v", err)
	}

	// Append third signature.
	err = AppendSignatureRAMP(req, body, "signer3.test", priv3, expires+2)
	if err != nil {
		t.Fatalf("AppendSignatureRAMP (third): %v", err)
	}

	// Verify all three signatures exist.
	allParams, _, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parseAllSignatures: %v", err)
	}
	if len(allParams) != 3 {
		t.Fatalf("want 3 signatures, got %d", len(allParams))
	}

	wantLabels := []string{"sig1", "sig2", "sig3"}
	wantKeyIDs := []string{"signer1.test", "signer2.test", "signer3.test"}
	wantPubs := []ed25519.PublicKey{pub1, pub2, pub3}

	for i := range allParams {
		verifySignatureAtIndex(t, req, allParams, body, i, wantLabels[i], wantKeyIDs[i], wantPubs[i])
	}
}

// TestAppendSignatureRAMP_PreservesExistingHeaders verifies that appending
// does NOT modify the existing Content-Digest or Authorization headers.
func TestAppendSignatureRAMP_PreservesExistingHeaders(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen 1: %v", err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen 2: %v", err)
	}

	body := []byte(`{"test":"preserve"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://broker.example/test", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "broker.example"
	req.Header.Set("Authorization", "Bearer original-token")

	now := signNow()
	expires := now.Add(100 * time.Second).Unix()

	// First signature.
	err = SignRequestRAMP(req, body, "first.test", priv1, expires)
	if err != nil {
		t.Fatalf("SignRequestRAMP: %v", err)
	}

	originalDigest := req.Header.Get("Content-Digest")
	originalAuth := req.Header.Get("Authorization")

	// Append second signature.
	err = AppendSignatureRAMP(req, body, "second.test", priv2, expires+1)
	if err != nil {
		t.Fatalf("AppendSignatureRAMP: %v", err)
	}

	// Verify headers were NOT modified.
	if req.Header.Get("Content-Digest") != originalDigest {
		t.Fatalf("Content-Digest changed: want %q, got %q",
			originalDigest, req.Header.Get("Content-Digest"))
	}
	if req.Header.Get("Authorization") != originalAuth {
		t.Fatalf("Authorization changed: want %q, got %q",
			originalAuth, req.Header.Get("Authorization"))
	}

	// Verify sig1 still validates under the canonical verifier.
	// VerifyRequest checks the first label, so the resolver needs only sig1's key.
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{"first.test": pub1})
	v, err := VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if err != nil {
		t.Fatalf("VerifyRequest sig1 after append: %v", err)
	}
	if v.Label != "sig1" {
		t.Fatalf("want label sig1, got %q", v.Label)
	}
}

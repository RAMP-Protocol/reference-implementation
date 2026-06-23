package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	created := int64(1700000000)
	expires := int64(1700000100)
	err = AppendSignatureRAMP(req, body, "agent.test", priv, created, expires)
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

	// Verify the signature validates under the canonical verifier (MED-03).
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{"agent.test": pub})
	v, err := VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(time.Unix(created, 0))})
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

// verifySignatureAtIndex is a helper that verifies a signature at a specific
// index in the params list.
func verifySignatureAtIndex(
	t *testing.T, req *http.Request,
	allParams []Params, sigMap map[string][]byte,
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
	base, err := buildSignatureBase(req, params)
	if err != nil {
		t.Fatalf("buildSignatureBase %s: %v", wantLabel, err)
	}
	if !ed25519.Verify(pub, []byte(base), sigMap[params.Label]) {
		t.Fatalf("%s verification failed", wantLabel)
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
	created := int64(1700000000)
	expires := int64(1700000100)
	err = SignRequestRAMP(req, body, "agent.test", agentPriv, created, expires)
	if err != nil {
		t.Fatalf("SignRequestRAMP (agent): %v", err)
	}

	// Broker appends signature (should create sig2).
	err = AppendSignatureRAMP(req, body, "broker.test", brokerPriv, created+1, expires+1)
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
	allParams, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parseAllSignatures: %v", err)
	}
	if len(allParams) != 2 {
		t.Fatalf("want 2 signatures, got %d", len(allParams))
	}

	verifySignatureAtIndex(t, req, allParams, sigMap, 0, "sig1", "agent.test", agentPub)
	verifySignatureAtIndex(t, req, allParams, sigMap, 1, "sig2", "broker.test", brokerPub)
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

	created := int64(1700000000)
	expires := int64(1700000100)

	// First signature.
	err = SignRequestRAMP(req, body, "signer1.test", priv1, created, expires)
	if err != nil {
		t.Fatalf("SignRequestRAMP: %v", err)
	}

	// Append second signature.
	err = AppendSignatureRAMP(req, body, "signer2.test", priv2, created+1, expires+1)
	if err != nil {
		t.Fatalf("AppendSignatureRAMP (second): %v", err)
	}

	// Append third signature.
	err = AppendSignatureRAMP(req, body, "signer3.test", priv3, created+2, expires+2)
	if err != nil {
		t.Fatalf("AppendSignatureRAMP (third): %v", err)
	}

	// Verify all three signatures exist.
	allParams, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parseAllSignatures: %v", err)
	}
	if len(allParams) != 3 {
		t.Fatalf("want 3 signatures, got %d", len(allParams))
	}

	wantLabels := []string{"sig1", "sig2", "sig3"}
	wantKeyIDs := []string{"signer1.test", "signer2.test", "signer3.test"}
	wantPubs := []ed25519.PublicKey{pub1, pub2, pub3}

	for i, params := range allParams {
		if params.Label != wantLabels[i] {
			t.Fatalf("signature %d: want label %s, got %s", i, wantLabels[i], params.Label)
		}
		if params.KeyID != wantKeyIDs[i] {
			t.Fatalf("signature %d: want keyid %s, got %s", i, wantKeyIDs[i], params.KeyID)
		}
		base, err := buildSignatureBase(req, params)
		if err != nil {
			t.Fatalf("buildSignatureBase sig%d: %v", i+1, err)
		}
		if !ed25519.Verify(wantPubs[i], []byte(base), sigMap[params.Label]) {
			t.Fatalf("sig%d verification failed", i+1)
		}
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

	created := int64(1700000000)
	expires := int64(1700000100)

	// First signature.
	err = SignRequestRAMP(req, body, "first.test", priv1, created, expires)
	if err != nil {
		t.Fatalf("SignRequestRAMP: %v", err)
	}

	originalDigest := req.Header.Get("Content-Digest")
	originalAuth := req.Header.Get("Authorization")

	// Append second signature.
	err = AppendSignatureRAMP(req, body, "second.test", priv2, created+1, expires+1)
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

	// Verify sig1 still validates under the canonical verifier (MED-03).
	// VerifyRequest checks the first label, so the resolver needs only sig1's key.
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{"first.test": pub1})
	v, err := VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(time.Unix(created, 0))})
	if err != nil {
		t.Fatalf("VerifyRequest sig1 after append: %v", err)
	}
	if v.Label != "sig1" {
		t.Fatalf("want label sig1, got %q", v.Label)
	}
}

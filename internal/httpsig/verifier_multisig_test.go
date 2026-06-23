package httpsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// addMultisigSignature appends a co-signature (label sig2) to an existing
// RAMP-signed request, signed by priv under keyID. It routes through the
// production AppendSignatureRAMP so the test exercises the real label-derivation
// and chain-link emission (sig2 covers "signature";key="sig1") rather than a
// hand-rolled twin that could drift from production. Content-Digest is preserved
// from sig1, so a nil body is fine here.
func addMultisigSignature(t *testing.T, req *http.Request, keyID string, priv ed25519.PrivateKey, created, expires int64) {
	t.Helper()
	if err := AppendSignatureRAMP(req, nil, keyID, priv, created, expires); err != nil {
		t.Fatalf("append signature: %v", err)
	}
}

func TestVerifyMultisigRequest_BothValid(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen2: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"foo"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)
	addMultisigSignature(t, req, "agent-demo.v2", priv2, now.Unix(), now.Add(30*time.Second).Unix())

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
		testKeyID:       pub1,
		"agent-demo.v2": pub2,
	})
	verified, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(verified) != 2 {
		t.Fatalf("got %d verified, want 2", len(verified))
	}
	if verified[0].Label != "sig1" || verified[0].KeyID != testKeyID {
		t.Fatalf("sig1 = %+v", verified[0])
	}
	if verified[1].Label != "sig2" || verified[1].KeyID != "agent-demo.v2" {
		t.Fatalf("sig2 = %+v", verified[1])
	}
}

func TestVerifyMultisigRequest_FirstInvalid(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	_, priv1Wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen1 wrong: %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen2: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"bar"}`)
	req := newRAMPSignedRequest(t, body, priv1Wrong, now)
	addMultisigSignature(t, req, "agent-demo.v2", priv2, now.Unix(), now.Add(30*time.Second).Unix())

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
		testKeyID:       pub1,
		"agent-demo.v2": pub2,
	})
	_, err = VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify, got %v", err)
	}
}

func TestVerifyMultisigRequest_SecondInvalid(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen2: %v", err)
	}
	_, priv2Wrong, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen2 wrong: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"baz"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)
	addMultisigSignature(t, req, "agent-demo.v2", priv2Wrong, now.Unix(), now.Add(30*time.Second).Unix())

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
		testKeyID:       pub1,
		"agent-demo.v2": pub2,
	})
	_, err = VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify, got %v", err)
	}
}

// TestVerifyMultisigRequest_SecondExpired pins the created/expires window on the
// appended-label (sig2) path: a valid sig1 with an EXPIRED sig2 must fail with
// ErrExpired. The single-sig path covers the window in verifier_test.go, but the
// multisig path enforces it independently per label inside verifySingleSignature
// (TQ-04) — this asserts an expired co-signature cannot ride through on a valid
// primary signature.
func TestVerifyMultisigRequest_SecondExpired(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen2: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"expired-sig2"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)
	// sig2 expired one second before the verifier's clock; sig1 still valid.
	addMultisigSignature(t, req, "agent-demo.v2", priv2, now.Add(-120*time.Second).Unix(), now.Add(-time.Second).Unix())

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
		testKeyID:       pub1,
		"agent-demo.v2": pub2,
	})
	_, err = VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired for expired sig2, got %v", err)
	}
}

// TestVerifyMultisigRequest_SignatureIsPerLabelReplayStable pins the replay-key
// contract documented on VerifiedRequest.Signature: the field is the per-label
// base64 signature value, not the whole multi-label Signature header. The
// replay store keys on (KeyID, Signature), so the agent's sig1 key MUST stay
// invariant when a broker re-wraps the same sig1 under a fresh sig2 — otherwise
// a relay can re-present a captured agent signature within its expires window
// without tripping the replay store.
func TestVerifyMultisigRequest_SignatureIsPerLabelReplayStable(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen1: %v", err)
	}
	pub2a, priv2a, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen2a: %v", err)
	}
	pub2b, priv2b, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen2b: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"foo"}`)
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
		testKeyID:        pub1,
		"broker.relay.a": pub2a,
		"broker.relay.b": pub2b,
	})
	opts := VerifyRequestOptions{Clk: clock.NewDeterministic(now)}

	// Request A: agent sig1 + broker relay-a sig2.
	reqA := newRAMPSignedRequest(t, body, priv1, now)
	addMultisigSignature(t, reqA, "broker.relay.a", priv2a, now.Unix(), now.Add(30*time.Second).Unix())
	verifiedA, err := VerifyMultisigRequest(reqA, resolver, opts)
	if err != nil {
		t.Fatalf("verify A: %v", err)
	}

	// The two co-signers must carry DISTINCT Signature values (the bug populated
	// both with the identical full header).
	if verifiedA[0].Signature == verifiedA[1].Signature {
		t.Fatalf("sig1 and sig2 share Signature %q — field carries the full header, not the per-label value",
			verifiedA[0].Signature)
	}
	// And each Signature is exactly the base64 of that label's own signature bytes.
	sig1Bytes, err := parseSignatureField(reqA.Header.Get("Signature"), "sig1")
	if err != nil {
		t.Fatalf("parse sig1: %v", err)
	}
	wantSig1 := base64.StdEncoding.EncodeToString(sig1Bytes)
	if verifiedA[0].Signature != wantSig1 {
		t.Fatalf("sig1 Signature = %q, want per-label %q", verifiedA[0].Signature, wantSig1)
	}

	// Request B: the SAME agent sig1 (same key, body, params → deterministic
	// ed25519), re-wrapped under a DIFFERENT broker sig2.
	reqB := newRAMPSignedRequest(t, body, priv1, now)
	addMultisigSignature(t, reqB, "broker.relay.b", priv2b, now.Unix(), now.Add(60*time.Second).Unix())
	verifiedB, err := VerifyMultisigRequest(reqB, resolver, opts)
	if err != nil {
		t.Fatalf("verify B: %v", err)
	}

	// Replay-store invariant: the agent label's key is identical across both
	// requests despite the broker re-wrapping.
	if verifiedA[0].Signature != verifiedB[0].Signature {
		t.Fatalf("agent sig1 replay key changed under broker re-wrap: A=%q B=%q",
			verifiedA[0].Signature, verifiedB[0].Signature)
	}
}

func TestVerifyMultisigRequest_SingleSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"single"}`)
	req := newRAMPSignedRequest(t, body, priv, now)

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	verified, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(verified) != 1 {
		t.Fatalf("got %d verified, want 1", len(verified))
	}
	if verified[0].KeyID != testKeyID {
		t.Fatalf("keyid = %q, want %q", verified[0].KeyID, testKeyID)
	}
}

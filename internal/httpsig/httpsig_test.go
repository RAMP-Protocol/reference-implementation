package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// The three tests below exercise digest/header negatives that the canonical
// VerifyRequest suite (verifier_test.go) does not otherwise cover. They were
// ported from the deleted legacy httpsig.Verify tests (MED-03) onto the
// canonical verifier using the shared newRAMPSignedRequest fixture + a fixed
// clock; the remaining legacy negatives (valid, wrong-key, unknown-key,
// missing-input, bad-alg) are already covered there and were dropped.

func TestVerifyRequest_TamperedBodyRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	req := newRAMPSignedRequest(t, []byte(`{"hello":"world"}`), priv, now)
	// Swap the body after signing: Content-Digest still commits to the original,
	// so the digest check (which runs before the ed25519 verify) must reject.
	req.Body = io.NopCloser(bytes.NewReader([]byte(`{"hello":"mars"}`)))

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
}

func TestVerifyRequest_MissingContentDigestRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	req := newRAMPSignedRequest(t, []byte(`{"hello":"world"}`), priv, now)
	req.Header.Del("Content-Digest")

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrMissingContentDigest) {
		t.Fatalf("want ErrMissingContentDigest, got %v", err)
	}
}

func TestVerifyRequest_MissingSignatureRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1700000000, 0)
	req := newRAMPSignedRequest(t, []byte(`{"hello":"world"}`), priv, now)
	req.Header.Del("Signature") // keep Signature-Input so the miss is on Signature

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{testKeyID: pub})
	_, err = VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("want ErrMissingSignature, got %v", err)
	}
}

// TestParseAllSignatures_ZeroSignatures verifies handling of empty headers.
func TestParseAllSignatures_ZeroSignatures(t *testing.T) {
	h := http.Header{}
	allParams, sigMap, err := parseAllSignatures(h)
	if !errors.Is(err, ErrMissingSignatureInput) {
		t.Fatalf("want ErrMissingSignatureInput, got %v", err)
	}
	if len(allParams) != 0 {
		t.Fatalf("want 0 params, got %d", len(allParams))
	}
	if len(sigMap) != 0 {
		t.Fatalf("want empty sigMap, got %d entries", len(sigMap))
	}
}

// TestParseAllSignatures_OneSignature verifies single-label parsing.
func TestParseAllSignatures_OneSignature(t *testing.T) {
	h := http.Header{}
	h.Set("Signature-Input", `sig1=("@method" "@path");keyid="caller.test";alg="ed25519";created=1700000000`)
	h.Set("Signature", `sig1=:YWJjZGVm:`)

	allParams, sigMap, err := parseAllSignatures(h)
	if err != nil {
		t.Fatalf("parseAllSignatures: %v", err)
	}
	if len(allParams) != 1 {
		t.Fatalf("want 1 params, got %d", len(allParams))
	}
	if allParams[0].Label != "sig1" {
		t.Fatalf("want label sig1, got %q", allParams[0].Label)
	}
	if allParams[0].KeyID != "caller.test" {
		t.Fatalf("want keyid caller.test, got %q", allParams[0].KeyID)
	}
	if len(sigMap) != 1 {
		t.Fatalf("want 1 sig, got %d", len(sigMap))
	}
	if _, ok := sigMap["sig1"]; !ok {
		t.Fatalf("sig1 not in sigMap")
	}
}

// TestParseAllSignatures_TwoSignatures verifies multi-label parsing.
func TestParseAllSignatures_TwoSignatures(t *testing.T) {
	h := http.Header{}
	h.Set("Signature-Input", `sig1=("@method" "@path");keyid="caller.test";alg="ed25519";created=1700000000, sig2=("@method");keyid="proxy.test";alg="ed25519";created=1700000001`)
	h.Set("Signature", `sig1=:YWJjZGVm:, sig2=:ZGVmZ2hp:`)

	allParams, sigMap, err := parseAllSignatures(h)
	if err != nil {
		t.Fatalf("parseAllSignatures: %v", err)
	}
	if len(allParams) != 2 {
		t.Fatalf("want 2 params, got %d", len(allParams))
	}
	if allParams[0].Label != "sig1" {
		t.Fatalf("want label sig1, got %q", allParams[0].Label)
	}
	if allParams[1].Label != "sig2" {
		t.Fatalf("want label sig2, got %q", allParams[1].Label)
	}
	if len(sigMap) != 2 {
		t.Fatalf("want 2 sigs, got %d", len(sigMap))
	}
	if _, ok := sigMap["sig1"]; !ok {
		t.Fatalf("sig1 not in sigMap")
	}
	if _, ok := sigMap["sig2"]; !ok {
		t.Fatalf("sig2 not in sigMap")
	}
}

// TestParseAllSignatures_MalformedMultiLabel verifies error handling.
func TestParseAllSignatures_MalformedMultiLabel(t *testing.T) {
	h := http.Header{}
	h.Set("Signature-Input", `sig1=("@method");keyid="caller.test";alg="ed25519", malformed`)
	h.Set("Signature", `sig1=:YWJjZGVm:`)

	_, _, err := parseAllSignatures(h)
	if !errors.Is(err, ErrMalformedSignatureInput) {
		t.Fatalf("want ErrMalformedSignatureInput, got %v", err)
	}
}

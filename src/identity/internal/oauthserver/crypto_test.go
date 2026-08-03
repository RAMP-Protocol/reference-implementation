package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// verifyPKCE is the OAuth server's code-interception defense: only the holder of the
// verifier that produced the challenge can redeem the code. The round-trip must hold,
// and a different verifier must NOT verify — the property the whole scheme rests on.
func TestVerifyPKCE_RoundTrip(t *testing.T) {
	verifier, err := randomToken(32)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	challenge := s256Challenge(verifier)
	if !verifyPKCE(challenge, verifier) {
		t.Error("verifyPKCE rejected the verifier that produced the challenge")
	}
	other, err := randomToken(32)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	if verifyPKCE(challenge, other) {
		t.Error("verifyPKCE accepted a verifier that did not produce the challenge")
	}
}

// s256Challenge must be exactly base64url(SHA-256(verifier)) with no padding (RFC 7636
// §4.2), so it interoperates with any conformant client's own challenge computation.
func TestS256Challenge_IsBase64URLSHA256(t *testing.T) {
	sum := sha256.Sum256([]byte("test-verifier"))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := s256Challenge("test-verifier"); got != want {
		t.Errorf("s256Challenge = %q, want %q", got, want)
	}
	if s256Challenge("a") == s256Challenge("b") {
		t.Error("distinct verifiers produced the same challenge")
	}
}

// sameToken (the CSRF and value comparison) must be exact-match and not accept a
// prefix or a differing value; the constant-time property is not observable in a test,
// but the equality contract is.
func TestSameToken(t *testing.T) {
	if !sameToken("abc123", "abc123") {
		t.Error("sameToken(equal) = false")
	}
	if sameToken("abc123", "abc124") {
		t.Error("sameToken(differing) = true")
	}
	if sameToken("abc123", "abc12") {
		t.Error("sameToken(prefix) = true")
	}
}

// hashCode is what an authorization code is stored as, so a database read cannot
// replay it: deterministic, collision-distinct, and never the code itself.
func TestHashCode(t *testing.T) {
	h1 := hashCode("code-1")
	if h1 != hashCode("code-1") {
		t.Error("hashCode is not deterministic")
	}
	if h1 == hashCode("code-2") {
		t.Error("distinct codes hashed to the same value")
	}
	if h1 == "code-1" {
		t.Error("hashCode returned the code verbatim; a DB read could replay it")
	}
}

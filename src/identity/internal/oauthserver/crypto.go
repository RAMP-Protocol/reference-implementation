package oauthserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// generateVerifier returns a high-entropy PKCE code verifier (RFC 7636 §4.1): 32
// random bytes base64url-encoded, comfortably inside the 43–128 character range.
// Used for the service's own (upstream) leg to Zitadel.
func generateVerifier() (string, error) {
	return randomToken(32)
}

// sha256b64url returns the base64url-encoded SHA-256 of s — the one hashing
// primitive both the S256 PKCE challenge and the stored-code hash are built from.
func sha256b64url(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// s256Challenge computes the S256 PKCE code challenge for a verifier (RFC 7636 §4.2).
func s256Challenge(verifier string) string {
	return sha256b64url(verifier)
}

// verifyPKCE reports, in constant time, whether verifier hashes to challenge under
// S256 — the check /token runs against the downstream client's stored challenge.
func verifyPKCE(challenge, verifier string) bool {
	want := s256Challenge(verifier)
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

// sameToken reports, in constant time, whether two opaque tokens are equal — used
// for the form CSRF check so the compare leaks no timing signal about the token.
func sameToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// randomToken returns n bytes of base64url-encoded randomness — the raw material for
// client IDs, authorization codes, states, and nonces.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauthserver: entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashCode returns the SHA-256 of an authorization code, base64url-encoded. Codes are
// stored only as this hash, so a database read cannot replay one.
func hashCode(code string) string {
	return sha256b64url(code)
}

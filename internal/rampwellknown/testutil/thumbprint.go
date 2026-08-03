package testutil

import (
	"crypto/ed25519"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// MustThumbprint returns the RFC 7638 thumbprint (the RFC 9421 keyid after the
// WBA split) of pub, failing the test on error.
func MustThumbprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return tp
}

// MustThumbprintKey returns the RFC 7638 thumbprint of a rampwellknown.Key.
func MustThumbprintKey(t *testing.T, k *rampwellknown.Key) string {
	t.Helper()
	tp, err := rampwellknown.Thumbprint(k)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return tp
}

// MustThumbprintPriv returns the thumbprint of priv's public key, panicking on
// error (for the non-*testing.T call site in exchange integration_helper_test.go).
func MustThumbprintPriv(priv ed25519.PrivateKey) string {
	tp, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	return tp
}

package testutil

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
)

// The one place a test builds an agent's signing key.
//
// The arrangement is three steps that have to agree: generate an ed25519 pair,
// derive the RFC 7638 thumbprint of the PUBLIC half, and hand the private half
// over under that thumbprint as the key id. The signer refuses to sign when the
// id and the key disagree, so a copy that derived the thumbprint from the wrong
// half would fail at signing time with an error about custody. It was written
// twice, once in each of rampclient's two test packages.
//
// This package depends on ramphttpsig and never the reverse, so a fixture here
// cannot be reached from ramphttpsig's own internal tests.

// AgentKey builds one agent's signing key, identified by directory.
func AgentKey(t *testing.T, directory string) ramphttpsig.AgentKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	kid, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint agent key: %v", err)
	}
	return ramphttpsig.AgentKey{Directory: directory, KeyID: kid, Private: priv}
}

// AgentKeySource wraps AgentKey as the per-request source a client is wired
// with. It answers with the same key for every context, which is what a test
// driving one agent wants; nothing here reads the identity off the context,
// because there is only one agent to be.
func AgentKeySource(t *testing.T, directory string) ramphttpsig.KeySource {
	t.Helper()
	key := AgentKey(t, directory)
	return func(context.Context) (ramphttpsig.AgentKey, error) { return key, nil }
}

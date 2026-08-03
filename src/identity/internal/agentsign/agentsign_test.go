package agentsign_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/agentsign"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// nonEd25519Custody stands in for a custody backend whose signer is not an
// ed25519 private key. The shipped Vault backend cannot produce this — it stores
// the key itself — so the branch is only reachable through a stub. It is worth a
// test anyway: this is exactly what an HSM or Transit backend WILL return, and the
// failure has to be a legible error rather than a panic at the signing library.
type nonEd25519Custody struct{}

func (nonEd25519Custody) Active(_ context.Context, subdomain string) (keystore.Key, error) {
	return keystore.Key{
		Ref:    keystore.Ref{Subdomain: subdomain, Thumbprint: "aXJyZWxldmFudC1idXQtd2VsbC1mb3JtZWQtdmFsdWU"},
		Window: keystore.Window{NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)},
	}, nil
}

func (nonEd25519Custody) Signer(_ context.Context, _ keystore.Ref) (crypto.Signer, error) {
	// Any signer that is not an ed25519 private key exercises the same branch.
	return rsa.GenerateKey(rand.Reader, 2048)
}

// TestKeyFor_RejectsAKeyItCannotRead pins the honest failure when custody will not
// surrender private key bytes: the request fails with ErrNotSignable rather than
// panicking inside the RFC 9421 signer or, worse, going out unsigned.
func TestKeyFor_RejectsAKeyItCannotRead(t *testing.T) {
	t.Parallel()
	resolver, err := agentsign.New(agentsign.Config{Keys: nonEd25519Custody{}})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}

	_, err = resolver.KeyFor(t.Context(), "alice.rampmcp.org")

	if !errors.Is(err, agentsign.ErrNotSignable) {
		t.Fatalf("err = %v, want ErrNotSignable", err)
	}
}

// TestSource_RefusesAContextWithoutAnIdentity pins the fail-closed rule at the
// seam itself, independently of any transport: no authenticated agent means no
// signature, never a default one.
func TestSource_RefusesAContextWithoutAnIdentity(t *testing.T) {
	t.Parallel()
	resolver, err := agentsign.New(agentsign.Config{Keys: nonEd25519Custody{}})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}

	_, err = resolver.Source()(t.Context())

	if !errors.Is(err, agentsign.ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
}

// TestNew_RequiresCustody pins that a misconfigured composition root fails at
// startup rather than nil-panicking on the first signed request.
func TestNew_RequiresCustody(t *testing.T) {
	t.Parallel()
	if _, err := agentsign.New(agentsign.Config{}); err == nil {
		t.Fatal("a Resolver was built with no custody backend")
	}
}

// TestSubdomainContext_RoundTrips pins the carrier the authenticating layer uses;
// an absent identity reads as empty, which is what Source refuses on.
func TestSubdomainContext_RoundTrips(t *testing.T) {
	t.Parallel()
	if got := agentsign.SubdomainFromContext(t.Context()); got != "" {
		t.Errorf("bare context carried %q, want empty", got)
	}
	ctx := agentsign.WithSubdomain(t.Context(), "alice.rampmcp.org")
	if got := agentsign.SubdomainFromContext(ctx); got != "alice.rampmcp.org" {
		t.Errorf("subdomain = %q, want alice.rampmcp.org", got)
	}
}

// interfaceGuard keeps the narrow custody port honest: the shipped Vault store
// must satisfy it, so a change to either side is a compile error here rather than
// a wiring failure in the composition root.
var _ agentsign.Custody = (*keystore.VaultStore)(nil)

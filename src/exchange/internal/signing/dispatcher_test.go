package signing_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

type stubStore struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	rsa  *rsa.PrivateKey
	err  error
}

func (s *stubStore) Ed25519(string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return s.pub, s.priv, s.err
}

func (s *stubStore) RSA(string) (*rsa.PrivateKey, error) {
	return s.rsa, s.err
}

func TestURLSignerFor_Ed25519(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := &stubStore{pub: pub, priv: priv}
	sgn, err := signing.URLSignerFor(signing.TenantKeys{Scheme: signing.SchemeEd25519, Ed25519Ref: "k"}, store)
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	// Behavioral check (the concrete type is an unexported SDK adapter): the
	// returned signer mints a URL that SDK-verifies against the tenant key and
	// carries the thumbprint kid.
	out, err := sgn.SignURL(context.Background(), "https://cdn.example/r", "", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verified, err := helpers.VerifyURLEd25519(out.URL, pub, time.Now())
	if err != nil {
		t.Fatalf("verify minted url: %v", err)
	}
	thumb, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if verified.KeyID != thumb {
		t.Fatalf("kid = %q, want thumbprint %q", verified.KeyID, thumb)
	}
}

func TestURLSignerFor_CloudFront(t *testing.T) {
	t.Parallel()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := &stubStore{rsa: priv}
	sgn, err := signing.URLSignerFor(signing.TenantKeys{
		Scheme:              signing.SchemeCFRSA,
		RSARef:              "k",
		CloudFrontKeyPairID: "APKATEST",
	}, store)
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	if _, ok := sgn.(*signing.CloudFrontURLSigner); !ok {
		t.Fatalf("got %T", sgn)
	}
}

func TestURLSignerFor_CloudFrontMissingKeyPairID(t *testing.T) {
	t.Parallel()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := &stubStore{rsa: priv}
	_, err := signing.URLSignerFor(signing.TenantKeys{Scheme: signing.SchemeCFRSA, RSARef: "k"}, store)
	if err == nil {
		t.Fatal("expected key pair id error")
	}
}

func TestURLSignerFor_UnknownScheme(t *testing.T) {
	t.Parallel()
	_, err := signing.URLSignerFor(signing.TenantKeys{Scheme: "BOGUS"}, &stubStore{})
	if err == nil {
		t.Fatal("expected unknown-scheme error")
	}
}

func TestURLSignerFor_StoreError(t *testing.T) {
	t.Parallel()
	want := errors.New("boom")
	_, err := signing.URLSignerFor(signing.TenantKeys{Scheme: signing.SchemeEd25519}, &stubStore{err: want})
	if err == nil {
		t.Fatal("expected store error")
	}
}

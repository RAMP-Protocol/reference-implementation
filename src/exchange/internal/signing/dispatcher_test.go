package signing_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

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
	if _, ok := sgn.(*signing.Ed25519URLSigner); !ok {
		t.Fatalf("got %T", sgn)
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

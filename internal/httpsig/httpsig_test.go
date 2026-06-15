package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func newSignedRequest(t *testing.T, body []byte, keyID string, priv ed25519.PrivateKey) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.CatalogService/PushResources", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "exchange.example"
	if err := SignRequest(req, body, keyID, priv, 1700000000); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

// makeFixedLookup returns a LookupKey that admits only callerTestKeyID.
const callerTestKeyID = "caller.test"

func makeFixedLookup(pub ed25519.PublicKey) LookupKey {
	return func(_ context.Context, k string) (ed25519.PublicKey, error) {
		if k != callerTestKeyID {
			return nil, ErrUnknownKey
		}
		return pub, nil
	}
}

func TestVerify_ValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, body, "caller.test", priv)

	v, err := Verify(context.Background(), req, body, makeFixedLookup(pub))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.KeyID != "caller.test" {
		t.Fatalf("keyid = %q, want caller.test", v.KeyID)
	}
}

func TestVerify_TamperedBodyRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, body, "caller.test", priv)

	tampered := []byte(`{"hello":"mars"}`)
	_, err = Verify(context.Background(), req, tampered, makeFixedLookup(pub))
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
}

func TestVerify_WrongKeyIDRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, body, "caller.test", priv)

	// Lookup returns the wrong pubkey — signature verification must fail.
	_, err = Verify(context.Background(), req, body, makeFixedLookup(wrongPub))
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify, got %v", err)
	}
}

func TestVerify_UnknownKeyIDReturnsLookupErr(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, body, "unknown.test", priv)

	sentinel := errors.New("not registered")
	_, err = Verify(context.Background(), req, body, func(_ context.Context, k string) (ed25519.PublicKey, error) {
		return nil, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel lookup err, got %v", err)
	}
}

func TestVerify_MissingContentDigestRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, body, "caller.test", priv)
	req.Header.Del("Content-Digest")

	_, err = Verify(context.Background(), req, body, makeFixedLookup(pub))
	if !errors.Is(err, ErrMissingContentDigest) {
		t.Fatalf("want ErrMissingContentDigest, got %v", err)
	}
}

func TestVerify_MissingSignatureInputRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, body, "caller.test", priv)
	req.Header.Del("Signature-Input")

	_, err = Verify(context.Background(), req, body, makeFixedLookup(pub))
	if !errors.Is(err, ErrMissingSignatureInput) {
		t.Fatalf("want ErrMissingSignatureInput, got %v", err)
	}
}

func TestVerify_MissingSignatureRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, body, "caller.test", priv)
	req.Header.Del("Signature")

	_, err = Verify(context.Background(), req, body, makeFixedLookup(pub))
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("want ErrMissingSignature, got %v", err)
	}
}

func TestVerify_UnsupportedAlgRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	req := newSignedRequest(t, body, "caller.test", priv)
	// Swap alg in Signature-Input to rsa — forces unsupported-alg rejection
	// even though the raw signature was produced with ed25519.
	input := req.Header.Get("Signature-Input")
	req.Header.Set("Signature-Input", strings.Replace(input, `alg="ed25519"`, `alg="rsa-pss-sha256"`, 1))

	_, err = Verify(context.Background(), req, body, makeFixedLookup(pub))
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("want ErrUnsupportedAlgorithm, got %v", err)
	}
}

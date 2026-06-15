package signing_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

func TestEd25519URLSigner_RoundTripVerifies(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signing.Ed25519URLSigner{Private: priv, Public: pub, KeyID: "k1"}
	expiry := time.Now().Add(5 * time.Minute).UTC()

	out, err := s.SignURL(context.Background(), "https://cdn.example/resource/abc", "", expiry)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := url.Parse(out.URL)
	if err != nil {
		t.Fatalf("parse out: %v", err)
	}
	q := parsed.Query()
	sigB64 := q.Get("sig")
	if sigB64 == "" {
		t.Fatal("sig param missing")
	}
	if q.Get("kid") != "k1" {
		t.Fatalf("kid param = %q", q.Get("kid"))
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	q.Del("sig")
	parsed.RawQuery = q.Encode()
	canonical := "GET\n" + parsed.String()
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatal("expected verification to succeed")
	}
	if len(out.Hash) != sha256.Size {
		t.Fatalf("hash len = %d", len(out.Hash))
	}
}

func TestEd25519URLSigner_EmbedsAgentIDUnderSignature(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signing.Ed25519URLSigner{Private: priv, Public: pub, KeyID: "k1"}
	const thumb = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

	out, err := s.SignURL(context.Background(), "https://cdn.example/r", thumb, time.Now().Add(time.Minute).UTC())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := url.Parse(out.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := parsed.Query()
	if got := q.Get(signing.AgentIDParam); got != thumb {
		t.Fatalf("agent_id = %q, want %q", got, thumb)
	}
	// The signature must cover agent_id: stripping only sig and verifying the
	// canonical message succeeds, but tampering agent_id breaks it.
	sig, err := base64.RawURLEncoding.DecodeString(q.Get("sig"))
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	q.Del("sig")
	parsed.RawQuery = q.Encode()
	if !ed25519.Verify(pub, []byte("GET\n"+parsed.String()), sig) {
		t.Fatal("expected verification with agent_id present to succeed")
	}
	q.Set(signing.AgentIDParam, "tampered")
	parsed.RawQuery = q.Encode()
	if ed25519.Verify(pub, []byte("GET\n"+parsed.String()), sig) {
		t.Fatal("expected agent_id tamper to invalidate signature")
	}
}

func TestEd25519URLSigner_EmptyAgentIDOmitsParam(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signing.Ed25519URLSigner{Private: priv, Public: pub, KeyID: "k1"}
	out, err := s.SignURL(context.Background(), "https://cdn.example/r", "", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, _ := url.Parse(out.URL)
	if parsed.Query().Has(signing.AgentIDParam) {
		t.Fatal("agent_id param must be absent for an unbound URL")
	}
}

func TestCloudFrontURLSigner_EmbedsAgentID(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	s := &signing.CloudFrontURLSigner{KeyPairID: "APKATESTKEY", PrivateKey: priv}
	const thumb = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	out, err := s.SignURL(context.Background(), "https://d1.cloudfront.net/x.jpg", thumb, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := url.Parse(out.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := parsed.Query().Get(signing.AgentIDParam); got != thumb {
		t.Fatalf("agent_id = %q, want %q", got, thumb)
	}
}

func TestEd25519URLSigner_TamperedURLFailsVerify(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signing.Ed25519URLSigner{Private: priv, Public: pub}
	out, err := s.SignURL(context.Background(), "https://cdn.example/a", "", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, _ := url.Parse(out.URL)
	q := parsed.Query()
	sig, _ := base64.RawURLEncoding.DecodeString(q.Get("sig"))
	// Tamper the path — the resource being signed for changes.
	parsed.Path = "/b"
	q.Del("sig")
	parsed.RawQuery = q.Encode()
	if ed25519.Verify(pub, []byte("GET\n"+parsed.String()), sig) {
		t.Fatal("expected path tamper to invalidate signature")
	}
}

func TestEd25519URLSigner_MissingKeyRejected(t *testing.T) {
	t.Parallel()
	s := &signing.Ed25519URLSigner{}
	if _, err := s.SignURL(context.Background(), "https://x.example/", "", time.Now()); err == nil {
		t.Fatal("expected missing-key error")
	}
}

func TestCloudFrontURLSigner_HappyPath(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	s := &signing.CloudFrontURLSigner{KeyPairID: "APKATESTKEY", PrivateKey: priv}
	out, err := s.SignURL(context.Background(), "https://d111111abcdef8.cloudfront.net/image.jpg", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if out.URL == "" {
		t.Fatal("empty url")
	}
	parsed, err := url.Parse(out.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := parsed.Query()
	for _, p := range []string{"Expires", "Signature", "Key-Pair-Id"} {
		if q.Get(p) == "" {
			t.Errorf("missing cloudfront param %q", p)
		}
	}
}

func TestCloudFrontURLSigner_MissingKey(t *testing.T) {
	t.Parallel()
	s := &signing.CloudFrontURLSigner{KeyPairID: "id"}
	if _, err := s.SignURL(context.Background(), "https://x.example/", "", time.Now()); err == nil {
		t.Fatal("expected missing private-key error")
	}
}

func TestCloudFrontURLSigner_MissingKeyPairID(t *testing.T) {
	t.Parallel()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := &signing.CloudFrontURLSigner{PrivateKey: priv}
	if _, err := s.SignURL(context.Background(), "https://x.example/", "", time.Now()); err == nil {
		t.Fatal("expected missing key pair id error")
	}
}

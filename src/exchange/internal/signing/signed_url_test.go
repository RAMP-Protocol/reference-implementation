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

	out, err := s.SignURL(context.Background(), "https://cdn.example/resource/abc", expiry)
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

func TestEd25519URLSigner_TamperedURLFailsVerify(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signing.Ed25519URLSigner{Private: priv, Public: pub}
	out, err := s.SignURL(context.Background(), "https://cdn.example/a", time.Now().Add(time.Minute))
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
	if _, err := s.SignURL(context.Background(), "https://x.example/", time.Now()); err == nil {
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
	out, err := s.SignURL(context.Background(), "https://d111111abcdef8.cloudfront.net/image.jpg", time.Now().Add(time.Hour))
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
	if _, err := s.SignURL(context.Background(), "https://x.example/", time.Now()); err == nil {
		t.Fatal("expected missing private-key error")
	}
}

func TestCloudFrontURLSigner_MissingKeyPairID(t *testing.T) {
	t.Parallel()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := &signing.CloudFrontURLSigner{PrivateKey: priv}
	if _, err := s.SignURL(context.Background(), "https://x.example/", time.Now()); err == nil {
		t.Fatal("expected missing key pair id error")
	}
}

func TestAppendAuditQueryParams_AddsAndPreserves(t *testing.T) {
	t.Parallel()
	out, err := signing.AppendAuditQueryParams(
		"https://cdn.example/r?keep=yes",
		map[string]string{"tx_id": "TX-1", "req_id": "R-2"},
	)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	parsed, err := url.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := parsed.Query()
	if q.Get("tx_id") != "TX-1" {
		t.Errorf("tx_id = %q", q.Get("tx_id"))
	}
	if q.Get("req_id") != "R-2" {
		t.Errorf("req_id = %q", q.Get("req_id"))
	}
	if q.Get("keep") != "yes" {
		t.Errorf("keep = %q", q.Get("keep"))
	}
}

func TestAppendAuditQueryParams_DropsEmpty(t *testing.T) {
	t.Parallel()
	out, _ := signing.AppendAuditQueryParams(
		"https://cdn.example/r", map[string]string{"tx_id": "T", "req_id": ""},
	)
	parsed, _ := url.Parse(out)
	if parsed.Query().Get("req_id") != "" {
		t.Error("empty req_id should be dropped")
	}
	if parsed.Query().Get("tx_id") != "T" {
		t.Errorf("tx_id = %q", parsed.Query().Get("tx_id"))
	}
}

func TestAppendAuditQueryParams_NoParamsIsIdentity(t *testing.T) {
	t.Parallel()
	in := "https://cdn.example/r?a=b"
	out, err := signing.AppendAuditQueryParams(in, nil)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if out != in {
		t.Errorf("expected identity, got %q", out)
	}
}

// Round-trip: an Ed25519-signed URL with audit params verifies because the
// audit params are present at canonicalization time and the verifier
// reconstructs the same canonical message.
func TestEd25519URLSigner_AuditParamsCoveredBySignature(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signing.Ed25519URLSigner{Private: priv, Public: pub, KeyID: "k1"}

	audited, err := signing.AppendAuditQueryParams(
		"https://cdn.example/resource/abc",
		map[string]string{"tx_id": "TX-FOO", "req_id": "R-BAR"},
	)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	out, err := s.SignURL(context.Background(), audited, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, _ := url.Parse(out.URL)
	q := parsed.Query()
	if q.Get("tx_id") != "TX-FOO" {
		t.Errorf("tx_id missing: %q", q.Get("tx_id"))
	}
	sig, _ := base64.RawURLEncoding.DecodeString(q.Get("sig"))
	q.Del("sig")
	parsed.RawQuery = q.Encode()
	if !ed25519.Verify(pub, []byte("GET\n"+parsed.String()), sig) {
		t.Fatal("expected verification with audit params to succeed")
	}
}

// Tampering with tx_id after signing must invalidate the signature — proves
// audit correlators are integrity-protected, not advisory.
func TestEd25519URLSigner_AuditParamTamperFailsVerify(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signing.Ed25519URLSigner{Private: priv, Public: pub}
	audited, _ := signing.AppendAuditQueryParams(
		"https://cdn.example/r", map[string]string{"tx_id": "TX-A"},
	)
	out, _ := s.SignURL(context.Background(), audited, time.Now().Add(time.Minute))
	parsed, _ := url.Parse(out.URL)
	q := parsed.Query()
	sig, _ := base64.RawURLEncoding.DecodeString(q.Get("sig"))
	q.Set("tx_id", "TX-B") // attacker swaps the correlator
	q.Del("sig")
	parsed.RawQuery = q.Encode()
	if ed25519.Verify(pub, []byte("GET\n"+parsed.String()), sig) {
		t.Fatal("expected tx_id tamper to invalidate signature")
	}
}

func TestExtractSignatureFromURL(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		in   string
		want string
	}{
		"cloudfront": {
			in:   "https://x.example/r?Expires=1&Signature=ABCDEF&Key-Pair-Id=K1",
			want: "ABCDEF",
		},
		"ed25519": {
			in:   "https://x.example/r?exp=1&sig=GHIJKL&kid=k1",
			want: "GHIJKL",
		},
		"prefers-Signature-when-both-present": {
			in:   "https://x.example/r?Signature=AAA&sig=BBB",
			want: "AAA",
		},
		"none": {
			in:   "https://x.example/r?other=zzz",
			want: "",
		},
		"unparseable": {
			in:   "://broken",
			want: "",
		},
	}
	for name, tc := range cases {
		got := signing.ExtractSignatureFromURL(tc.in)
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

// CloudFront canned-policy: the URL passed to cfsign is the policy Resource,
// so audit params present at sign time stay on the returned URL alongside
// Expires/Signature/Key-Pair-Id.
func TestCloudFrontURLSigner_AuditParamsSurviveSigning(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	s := &signing.CloudFrontURLSigner{KeyPairID: "APKATESTKEY", PrivateKey: priv}
	audited, _ := signing.AppendAuditQueryParams(
		"https://d111111abcdef8.cloudfront.net/image.jpg",
		map[string]string{"tx_id": "TX-CF", "req_id": "R-CF"},
	)
	out, err := s.SignURL(context.Background(), audited, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, _ := url.Parse(out.URL)
	q := parsed.Query()
	if q.Get("tx_id") != "TX-CF" {
		t.Errorf("tx_id missing on cloudfront url: %q", q.Get("tx_id"))
	}
	if q.Get("req_id") != "R-CF" {
		t.Errorf("req_id missing on cloudfront url: %q", q.Get("req_id"))
	}
	for _, p := range []string{"Expires", "Signature", "Key-Pair-Id"} {
		if q.Get(p) == "" {
			t.Errorf("missing cloudfront param %q", p)
		}
	}
}

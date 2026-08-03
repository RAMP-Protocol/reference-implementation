package pemkeys_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/pemkeys"
)

// The promise this package exists to keep: a key exported from the Identity
// Service can be re-imported and still signs what its public half verifies. A
// round-trip that loses the key is the "you own your identity" claim quietly
// broken, so it is asserted end to end rather than by comparing bytes.
func TestRoundTripKeySurvivesAndStillSigns(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	encoded, err := pemkeys.MarshalEd25519Private(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	reimported, err := pemkeys.ParseEd25519Private(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !bytes.Equal(reimported, priv) {
		t.Error("re-imported key differs from the exported one")
	}
	msg := []byte("a request the agent signs after moving to self-custody")
	if !ed25519.Verify(pub, msg, ed25519.Sign(reimported, msg)) {
		t.Error("signature from the re-imported key does not verify against the original public key")
	}
}

// openssl writes Ed25519 as PKCS#8 under a "PRIVATE KEY" header; the Exchange
// loads operator-provisioned keys in exactly that shape, so the block type is
// part of the contract, not an implementation detail.
func TestMarshalEmitsPKCS8PrivateKeyBlock(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded, err := pemkeys.MarshalEd25519Private(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("output is not a PEM document")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("PEM block type = %q, want %q", block.Type, "PRIVATE KEY")
	}
}

func TestParseRejectsNonEd25519Input(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal rsa: %v", err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})

	tests := map[string]struct {
		input []byte
		want  string
	}{
		// An RSA key parses as valid PKCS#8 — only the type assertion catches it.
		// Returning it as a nil ed25519 key would fail much later, at signing time.
		"an RSA key in a PKCS#8 PEM": {input: rsaPEM, want: "expected ed25519"},
		"not PEM at all":             {input: []byte("-----nonsense-----"), want: "no PEM block"},
		"empty input":                {input: nil, want: "no PEM block"},
		"PEM wrapping garbage": {
			input: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not DER")}),
			want:  "parse pkcs8",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key, err := pemkeys.ParseEd25519Private(tc.input)
			if err == nil {
				t.Fatalf("parse accepted %s", name)
			}
			if key != nil {
				t.Error("a rejected input still returned a key")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

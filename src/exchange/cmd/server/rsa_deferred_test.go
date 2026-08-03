package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// The RSA signing key is needed only by tenants on the AWS_CLOUDFRONT_RSA
// scheme — CloudFront verifies RSA signed URLs natively at the edge, while
// Cloudflare and Fastly publishers verify Ed25519 in the edge worker. These
// tests pin the boot contract that follows from that: an absent RSA key is not
// a boot failure, a present-but-broken one is, and the deferred absence must
// still name the setting an operator has to fix.

// writeEd25519KeyEnv points the Ed25519 resolver at a freshly generated key.
// That key IS unconditionally required — every tenant signs offers with it — so
// every case here has to supply one before the RSA branch is even reached.
func writeEd25519KeyEnv(t *testing.T) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	t.Setenv("RAMP_ED25519_PRIVATE_PEM",
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	t.Setenv("RAMP_ED25519_PRIVATE_PEM_FILE", "")
}

// TestSetupDemoKeys_BootsWithoutRSAKey is the headline behaviour: a deployment
// with no CloudFront-scheme tenant must not be forced to generate and mount an
// RSA key it will never use.
func TestSetupDemoKeys_BootsWithoutRSAKey(t *testing.T) {
	writeEd25519KeyEnv(t)
	t.Setenv("RAMP_RSA_PRIVATE_PEM", "")
	t.Setenv("RAMP_RSA_PRIVATE_PEM_FILE", "")

	keys, err := setupDemoKeys(discardLogger())
	if err != nil {
		t.Fatalf("boot must succeed with no RSA key configured: %v", err)
	}
	if keys.offerSigner == nil || keys.keystore == nil {
		t.Fatal("boot returned an incomplete key set")
	}
}

// TestSetupDemoKeys_DefersRSAFailureToLookup pairs with the test above: skipping
// the boot error must not silently produce a keystore that yields a useless
// "not found" when a CloudFront tenant finally arrives.
func TestSetupDemoKeys_DefersRSAFailureToLookup(t *testing.T) {
	writeEd25519KeyEnv(t)
	t.Setenv("RAMP_RSA_PRIVATE_PEM", "")
	t.Setenv("RAMP_RSA_PRIVATE_PEM_FILE", "")
	t.Setenv("RAMP_DEMO_RSA_KEY_REF", "cf-rsa-primary")

	keys, err := setupDemoKeys(discardLogger())
	if err != nil {
		t.Fatalf("setupDemoKeys: %v", err)
	}
	_, err = keys.keystore.RSA("cf-rsa-primary")
	if err == nil {
		t.Fatal("want a refusal when the deferred RSA key is looked up")
	}
	// The sentinel is what the service layer classifies on to answer
	// FailedPrecondition instead of Internal; the env names are what the
	// operator acts on. Both must survive.
	if !errors.Is(err, signing.ErrRSAKeyUnavailable) {
		t.Errorf("the refusal must wrap signing.ErrRSAKeyUnavailable; got %v", err)
	}
	for _, want := range []string{"RAMP_RSA_PRIVATE_PEM", "RAMP_RSA_PRIVATE_PEM_FILE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %s; got %v", want, err)
		}
	}
}

// TestSetupDemoKeys_FailsOnMalformedRSAKey keeps the fail-fast half of the old
// contract. An operator who configured a key plainly intends to use it, so a
// key that cannot be parsed is a mis-provisioned stack and must stop the boot —
// deferral applies to an ABSENT key, not a broken one.
func TestSetupDemoKeys_FailsOnMalformedRSAKey(t *testing.T) {
	writeEd25519KeyEnv(t)
	// Encoded rather than written as a literal, the same way writeEd25519KeyEnv
	// above builds its key. A literal BEGIN header followed by a matching END
	// footer is what the secret scanner matches on, and it reports the pair even
	// when the body between them decodes to the word "notakey".
	t.Setenv("RAMP_RSA_PRIVATE_PEM",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("notakey")})))
	t.Setenv("RAMP_RSA_PRIVATE_PEM_FILE", "")

	if _, err := setupDemoKeys(discardLogger()); err == nil {
		t.Fatal("a configured-but-unparseable RSA key must fail the boot")
	}
}

// TestSetupDemoKeys_LoadsConfiguredRSAKey guards against the deferral quietly
// breaking the CloudFront path it was carved around.
func TestSetupDemoKeys_LoadsConfiguredRSAKey(t *testing.T) {
	writeEd25519KeyEnv(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	path := filepath.Join(t.TempDir(), "rsa.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv("RAMP_RSA_PRIVATE_PEM", "")
	t.Setenv("RAMP_RSA_PRIVATE_PEM_FILE", path)
	t.Setenv("RAMP_DEMO_RSA_KEY_REF", "cf-rsa-primary")

	keys, err := setupDemoKeys(discardLogger())
	if err != nil {
		t.Fatalf("setupDemoKeys: %v", err)
	}
	got, err := keys.keystore.RSA("cf-rsa-primary")
	if err != nil {
		t.Fatalf("a configured RSA key must resolve: %v", err)
	}
	if !got.Equal(priv) {
		t.Fatal("keystore returned a different RSA key than was configured")
	}
}

package signing_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
)

func TestCoSigner_StampIntermediary_AddsHopAndSigns(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := signing.NewCoSigner("broker.example", "broker-1", priv)
	if err != nil {
		t.Fatalf("NewCoSigner: %v", err)
	}
	req := &rampv1.ResourceQuery{Id: "q-123"}

	sig, err := signer.StampIntermediary(req)
	if err != nil {
		t.Fatalf("StampIntermediary: %v", err)
	}

	if len(req.GetIntermediaries()) != 1 {
		t.Fatalf("expected 1 intermediary hop, got %d", len(req.GetIntermediaries()))
	}
	hop := req.GetIntermediaries()[0]
	if hop.GetDomain() != "broker.example" {
		t.Errorf("hop domain = %q, want broker.example", hop.GetDomain())
	}
	if hop.GetId() != "broker-1" {
		t.Errorf("hop id = %q, want broker-1", hop.GetId())
	}
	decoded, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(decoded) != ed25519.SignatureSize {
		t.Errorf("signature size = %d, want %d", len(decoded), ed25519.SignatureSize)
	}
}

func TestCoSigner_NewCoSigner_RejectsBadKey(t *testing.T) {
	_, err := signing.NewCoSigner("d", "id", ed25519.PrivateKey([]byte("short")))
	if err == nil {
		t.Fatal("expected error for short private key")
	}
}

func TestCoSigner_NewCoSigner_RejectsEmptyDomain(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := signing.NewCoSigner("", "broker-1", priv); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestLoadFromEnv_Seed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	seed := priv.Seed()
	encoded := base64.RawURLEncoding.EncodeToString(seed)
	t.Setenv("BROKER_ED25519_SEED", encoded)

	signer, err := signing.LoadFromEnv("broker.example", "broker-1")
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	// Public key should be derivable from seed.
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	got := signer.PublicKey()
	if !bytes.Equal(want, got) {
		t.Error("public key mismatch")
	}
}

func TestLoadFromEnv_Ephemeral(t *testing.T) {
	t.Setenv("BROKER_ED25519_SEED", "")
	t.Setenv("BROKER_ED25519_KEY_FILE", "")
	signer, err := signing.LoadFromEnv("broker.example", "broker-1")
	if err != nil {
		t.Fatalf("LoadFromEnv ephemeral: %v", err)
	}
	if got := signer.PublicKey(); len(got) != ed25519.PublicKeySize {
		t.Errorf("ephemeral public key size = %d", len(got))
	}
}

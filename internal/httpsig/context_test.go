package httpsig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestAllSignaturesFromContext_NilContext(t *testing.T) {
	ctx := context.Background()
	sigs := AllSignaturesFromContext(ctx)
	if sigs != nil {
		t.Fatalf("AllSignaturesFromContext on empty context = %+v, want nil", sigs)
	}
}

func TestAllSignaturesFromContext_SingleSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	v := &VerifiedRequest{
		KeyID:     "key1",
		Algorithm: "ed25519",
		Label:     "sig1",
		Signature: "abc123",
		Created:   1700000000,
		Expires:   1700000300,
		PublicKey: pub,
	}
	ctx := NewMultisigContext(context.Background(), []VerifiedRequest{*v})
	sigs := AllSignaturesFromContext(ctx)
	if len(sigs) != 1 {
		t.Fatalf("AllSignaturesFromContext returned %d sigs, want 1", len(sigs))
	}
	if sigs[0].KeyID != "key1" {
		t.Fatalf("sig[0].KeyID = %q, want %q", sigs[0].KeyID, "key1")
	}
}

func TestAllSignaturesFromContext_MultipleSignatures(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pub1: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pub2: %v", err)
	}
	v1 := VerifiedRequest{
		KeyID:     "key1",
		Algorithm: "ed25519",
		Label:     "sig1",
		Signature: "abc123",
		Created:   1700000000,
		Expires:   1700000300,
		PublicKey: pub1,
	}
	v2 := VerifiedRequest{
		KeyID:     "key2",
		Algorithm: "ed25519",
		Label:     "sig2",
		Signature: "def456",
		Created:   1700000000,
		Expires:   1700000300,
		PublicKey: pub2,
	}
	ctx := NewMultisigContext(context.Background(), []VerifiedRequest{v1, v2})
	sigs := AllSignaturesFromContext(ctx)
	if len(sigs) != 2 {
		t.Fatalf("AllSignaturesFromContext returned %d sigs, want 2", len(sigs))
	}
	if sigs[0].KeyID != "key1" {
		t.Fatalf("sig[0].KeyID = %q, want %q", sigs[0].KeyID, "key1")
	}
	if sigs[1].KeyID != "key2" {
		t.Fatalf("sig[1].KeyID = %q, want %q", sigs[1].KeyID, "key2")
	}
}

func TestFromContext_BackwardCompatWithMultisig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	v := VerifiedRequest{
		KeyID:     "key1",
		Algorithm: "ed25519",
		Label:     "sig1",
		Signature: "abc123",
		Created:   1700000000,
		Expires:   1700000300,
		PublicKey: pub,
	}
	ctx := NewMultisigContext(context.Background(), []VerifiedRequest{v})
	sig := FromContext(ctx)
	if sig == nil {
		t.Fatalf("FromContext returned nil, want first signature")
	}
	if sig.KeyID != "key1" {
		t.Fatalf("FromContext().KeyID = %q, want %q", sig.KeyID, "key1")
	}
}

func TestFromContext_BackwardCompatWithOldContext(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	v := &VerifiedRequest{
		KeyID:     "key1",
		Algorithm: "ed25519",
		Label:     "sig1",
		Signature: "abc123",
		Created:   1700000000,
		Expires:   1700000300,
		PublicKey: pub,
	}
	// Use old NewContext which stores single *VerifiedRequest
	ctx := NewContext(context.Background(), v)
	sig := FromContext(ctx)
	if sig == nil {
		t.Fatalf("FromContext returned nil, want signature")
	}
	if sig.KeyID != "key1" {
		t.Fatalf("FromContext().KeyID = %q, want %q", sig.KeyID, "key1")
	}
}

package signing_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// SignOffer now delegates to the protocol SDK (helpers.SignOffer), whose
// canonical payload covers the WHOLE Offer with ONLY the signature fields
// cleared — expires_at INCLUDED. These tests assert that contract by verifying
// through helpers.VerifyOffer (the same primitive the execute path's
// VerifyPresentedOffer is built on); the SDK owns the exhaustive offer-signature
// test matrix, so here we only pin the integration: this signer produces a
// signature the SDK accepts, and a tamper of any covered field (including
// expires_at) is rejected.

func TestEd25519Signer_SignProducesSDKVerifiableSignature(t *testing.T) {
	t.Parallel()
	signer, err := signing.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	offer := newOffer()
	sig, err := signer.SignOffer(offer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := helpers.VerifyOffer(offer, sig, signer.PublicKey()); err != nil {
		t.Fatalf("SDK verify of signer output: %v", err)
	}
}

func TestEd25519Signer_SignatureStableWithEmbeddedSigAndAlg(t *testing.T) {
	t.Parallel()
	signer, _ := signing.GenerateEd25519Signer()
	offer := newOffer()
	sig, err := signer.SignOffer(offer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Caller embeds signature + alg (as discover.go does) and re-verifies. The
	// canonical payload clears both before hashing, so verify must still pass.
	offer.Signature = sig
	offer.SignatureAlgorithm = signing.SignatureAlgorithm
	if err := helpers.VerifyOffer(offer, sig, signer.PublicKey()); err != nil {
		t.Fatalf("verify post-embed: %v", err)
	}
}

// TestEd25519Signer_ExpiresAtIsCovered locks the source-of-truth fix: the old
// service-local signer cleared expires_at from the canonical payload (so a
// relaying party could silently extend a TTL). The SDK keeps expires_at in the
// payload, so mutating it after signing MUST break verification.
func TestEd25519Signer_ExpiresAtIsCovered(t *testing.T) {
	t.Parallel()
	signer, _ := signing.GenerateEd25519Signer()
	offer := newOffer()
	offer.ExpiresAt = timestamppb.New(time.Unix(1_700_000_000, 0).UTC())
	sig, err := signer.SignOffer(offer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Extend the TTL after signing — the classic relay attack the SDK forbids.
	offer.ExpiresAt = timestamppb.New(time.Unix(1_900_000_000, 0).UTC())
	if err := helpers.VerifyOffer(offer, sig, signer.PublicKey()); err == nil {
		t.Fatal("expected verification to fail after mutating the signed expires_at")
	}
}

func TestEd25519Signer_TamperedPayloadRejected(t *testing.T) {
	t.Parallel()
	signer, _ := signing.GenerateEd25519Signer()
	offer := newOffer()
	sig, _ := signer.SignOffer(offer)
	offer.OfferId = "tampered"
	if err := helpers.VerifyOffer(offer, sig, signer.PublicKey()); err == nil {
		t.Fatal("expected tampered offer to fail verification")
	}
}

func TestEd25519Signer_WrongKeyRejected(t *testing.T) {
	t.Parallel()
	signerA, _ := signing.GenerateEd25519Signer()
	signerB, _ := signing.GenerateEd25519Signer()
	offer := newOffer()
	sig, _ := signerA.SignOffer(offer)
	if err := helpers.VerifyOffer(offer, sig, signerB.PublicKey()); err == nil {
		t.Fatal("expected wrong key to fail verification")
	}
}

func TestNewEd25519Signer_LengthValidation(t *testing.T) {
	t.Parallel()
	_, err := signing.NewEd25519Signer(ed25519.PublicKey{0}, ed25519.PrivateKey{0})
	if err == nil {
		t.Fatal("expected length error")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := signing.NewEd25519Signer(pub, priv); err != nil {
		t.Fatalf("good keys: %v", err)
	}
}

func newOffer() *rampv1.Offer {
	return &rampv1.Offer{
		OfferId:        "off-001",
		DeliveryMethod: rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		Pricing:        &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD"},
		IabCategories:  []string{"IAB1"},
	}
}

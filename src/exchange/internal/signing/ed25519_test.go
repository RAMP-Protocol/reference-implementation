package signing_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

func TestEd25519Signer_SignAndVerifyOffer(t *testing.T) {
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
	if err := signing.VerifyOffer(offer, sig, signer.PublicKey()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestEd25519Signer_SignatureStableAcrossClears(t *testing.T) {
	t.Parallel()
	signer, _ := signing.GenerateEd25519Signer()
	offer := newOffer()
	sig, err := signer.SignOffer(offer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Caller embeds signature + alg and re-verifies. Verify must tolerate that.
	offer.Signature = sig
	offer.SignatureAlgorithm = signing.SignatureAlgorithm
	if err := signing.VerifyOffer(offer, sig, signer.PublicKey()); err != nil {
		t.Fatalf("verify post-embed: %v", err)
	}
}

func TestVerifyOffer_TamperedPayloadRejected(t *testing.T) {
	t.Parallel()
	signer, _ := signing.GenerateEd25519Signer()
	offer := newOffer()
	sig, _ := signer.SignOffer(offer)
	offer.OfferId = "tampered"
	if err := signing.VerifyOffer(offer, sig, signer.PublicKey()); err == nil {
		t.Fatal("expected tampered offer to fail verification")
	}
}

func TestVerifyOffer_WrongKeyRejected(t *testing.T) {
	t.Parallel()
	signerA, _ := signing.GenerateEd25519Signer()
	signerB, _ := signing.GenerateEd25519Signer()
	offer := newOffer()
	sig, _ := signerA.SignOffer(offer)
	if err := signing.VerifyOffer(offer, sig, signerB.PublicKey()); err == nil {
		t.Fatal("expected wrong key to fail verification")
	}
}

func TestVerifyOffer_BadHex(t *testing.T) {
	t.Parallel()
	signer, _ := signing.GenerateEd25519Signer()
	if err := signing.VerifyOffer(newOffer(), "zz", signer.PublicKey()); err == nil {
		t.Fatal("expected bad hex to fail")
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
		Pricing:        &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_ACCESS, Rate: 0.05, Currency: "USD"},
		IabCategories:  []string{"IAB1"},
		ExtCritical:    nil,
	}
}

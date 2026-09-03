// Package signing produces and verifies the cryptographic signatures that bind
// Exchange offers and signed URLs. Ed25519 is the default scheme; RSA (for
// AWS CloudFront signed URLs) lives alongside it and is selected per tenant.
//
// Offer signing delegates to the protocol SDK (helpers.SignOffer), whose
// canonical payload covers the WHOLE Offer (expires_at included) with only the
// signature fields cleared — the reference behavior every RAMP party shares.
// The private key stays encapsulated in this package; the SDK never sees it
// except through this signer.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Ed25519Signer holds a single Ed25519 key pair and produces Offer signatures.
type Ed25519Signer struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// NewEd25519Signer wraps an existing key pair.
func NewEd25519Signer(pub ed25519.PublicKey, priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519: private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &Ed25519Signer{public: pub, private: priv}, nil
}

// GenerateEd25519Signer returns a freshly generated signer.
func GenerateEd25519Signer() (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	return &Ed25519Signer{public: pub, private: priv}, nil
}

// PublicKey returns a copy of the public key bytes.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(s.public))
	copy(out, s.public)
	return out
}

// PublicKeyB64URL returns the public key as unpadded base64url (JWK-friendly).
func (s *Ed25519Signer) PublicKeyB64URL() string {
	return base64.RawURLEncoding.EncodeToString(s.public)
}

// SignatureAlgorithm is the algorithm name "EdDSA" carried on
// Offer.signature_algorithm (which the canonical payload clears before signing).
// It mirrors helpers.OfferSignatureAlgorithm. The name is the one JOSE registers
// for Ed25519, but Offer.signature itself is a hex-encoded detached Ed25519
// signature — not a JWS, and not any other JOSE object.
const SignatureAlgorithm = helpers.OfferSignatureAlgorithm

// SignOffer signs offer with the encapsulated private key and returns the
// hex-encoded Ed25519 signature. It delegates to helpers.SignOffer so the
// canonical payload — the WHOLE Offer with only the signature fields cleared,
// expires_at INCLUDED — matches what every RAMP verifier (the SDK's
// VerifyPresentedOffer at execute) recomputes. The private key never leaves this
// package; the SDK receives it only via this call.
func (s *Ed25519Signer) SignOffer(offer *rampv1.Offer) (string, error) {
	sig, err := helpers.SignOffer(s.private, offer)
	if err != nil {
		return "", fmt.Errorf("sign offer: %w", err)
	}
	return sig, nil
}

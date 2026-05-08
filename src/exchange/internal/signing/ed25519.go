// Package signing produces and verifies the cryptographic signatures that bind
// Exchange offers and signed URLs. Ed25519 is the default scheme; RSA (for
// AWS CloudFront signed URLs) lives alongside it and is selected per tenant.
//
// The offer signer operates on the canonical protobuf encoding of the Offer
// with its signature fields cleared, so verifiers can recompute the payload
// deterministically without server-side offer storage.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
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

// SignatureAlgorithm returns the JWS alg value advertised on offers.
const SignatureAlgorithm = "EdDSA"

// SignOffer signs the canonical protobuf encoding of the Offer after clearing
// any existing signature fields. The hex-encoded signature is returned.
func (s *Ed25519Signer) SignOffer(offer *rampv1.Offer) (string, error) {
	payload, err := canonicalOfferPayload(offer)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.private, payload)
	return hex.EncodeToString(sig), nil
}

// VerifyOffer verifies signatureHex against offer using pub.
func VerifyOffer(offer *rampv1.Offer, signatureHex string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519: public key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := canonicalOfferPayload(offer)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrSignatureInvalid
	}
	return nil
}

// ErrSignatureInvalid signals verification failure (wrong key or tampered payload).
var ErrSignatureInvalid = errors.New("signing: offer signature invalid")

// canonicalOfferPayload returns the deterministic byte sequence the signer
// operates on. Protobuf marshalling is deterministic-enough for single-writer
// signing when the signature fields are cleared; callers never compare bytes
// across producers with different library versions.
func canonicalOfferPayload(offer *rampv1.Offer) ([]byte, error) {
	if offer == nil {
		return nil, errors.New("signing: offer is nil")
	}
	clone, ok := proto.Clone(offer).(*rampv1.Offer)
	if !ok {
		return nil, errors.New("signing: offer clone type mismatch")
	}
	clone.Signature = ""
	clone.SignatureAlgorithm = ""
	// Expiry is bound to offer issuance time, not the offer's resource/pricing
	// identity. Exchanges reissue offers with fresh expiries on every discovery
	// call, so excluding it from the canonical payload lets stateless
	// verification rebuild the same payload from the catalog alone.
	clone.ExpiresAt = nil
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("marshal offer: %w", err)
	}
	return data, nil
}

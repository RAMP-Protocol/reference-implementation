package rampwellknown

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"
)

// EncodeEd25519X encodes a raw Ed25519 public key as a JWK `x` parameter:
// base64url without padding (RFC 8037). It is the inverse of DecodeEd25519X;
// every producer of a JWKS `x` (here and the Broker key registry) uses it so the
// encoding has one source.
func EncodeEd25519X(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// DecodeEd25519X decodes a JWK `x` parameter — base64url (no padding) of a raw
// 32-byte Ed25519 public key (RFC 8037) — into an ed25519.PublicKey. A bad
// encoding or a wrong byte length is ErrSchemaInvalid. Shared by PublicKey and
// any consumer that validates a JWKS `x` (the Broker key registry) so the
// "32-byte Ed25519 x" contract has a single implementation.
func DecodeEd25519X(x string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("%w: decode x: %w", ErrSchemaInvalid, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: x is %d bytes, want %d",
			ErrSchemaInvalid, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// NewKey builds a published JWK for an Ed25519 public key valid over the
// half-open window [notBefore, notAfter). Producers use this so every role
// emits an identical JWK shape (RFC 8037: kty=OKP, crv=Ed25519, use=sig,
// alg=EdDSA, x=base64url(pub)).
func NewKey(kid string, pub ed25519.PublicKey, notBefore, notAfter time.Time) *Key {
	return &Key{
		Kid:       kid,
		Kty:       "OKP",
		Crv:       "Ed25519",
		Use:       "sig",
		Alg:       "EdDSA",
		X:         EncodeEd25519X(pub),
		NotBefore: notBefore.UTC().Format(time.RFC3339),
		NotAfter:  notAfter.UTC().Format(time.RFC3339),
	}
}

// KeyFromEncodedX builds a published JWK from an already-base64url x parameter
// (RFC 8037 raw 32-byte public key) and pre-formatted RFC 3339 validity bounds.
// Use it when the key bytes are already encoded — e.g. folding a registry JWKS
// into a manifest; reach for NewKey instead when the key is a raw ed25519.PublicKey.
func KeyFromEncodedX(kid, x, notBefore, notAfter string) *Key {
	return &Key{
		Kid:       kid,
		Kty:       "OKP",
		Crv:       "Ed25519",
		Use:       "sig",
		Alg:       "EdDSA",
		X:         x,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
}

// ActiveKeys returns the manifest keys whose validity window covers now,
// preserving document order. The window is half-open: a key is active when
// not_before <= now < not_after (lower bound inclusive, upper bound strict),
// matching the proto contract and avoiding a double-active instant at rotation.
// Keys with unparseable timestamps are skipped, not fatal.
func ActiveKeys(m *Manifest, now time.Time) []*Key {
	if m == nil {
		return nil
	}
	active := make([]*Key, 0, len(m.GetPublicKeys()))
	for _, k := range m.GetPublicKeys() {
		if keyActiveAt(k, now) {
			active = append(active, k)
		}
	}
	return active
}

// ActiveKey returns the Ed25519 public key of the first currently-valid key in
// document order, or ErrKeyExpired when no key's validity window covers now.
// Unlike LookupKey (which matches a known kid), this selects an identity's
// "current" signing key when the kid is not known ahead of time — the shape a
// caller resolving an agent/publisher by domain anchor needs (the transport
// keyID is the identity, not a key label). A malformed key `x` yields the
// decode error from PublicKey.
func ActiveKey(m *Manifest, now time.Time) (ed25519.PublicKey, error) {
	active := ActiveKeys(m, now)
	if len(active) == 0 {
		return nil, ErrKeyExpired
	}
	return PublicKey(active[0])
}

// KeyByKid returns the key carrying kid and whether it was found. Kids are
// unique within a single manifest's public_keys list.
func KeyByKid(m *Manifest, kid string) (*Key, bool) {
	if m == nil || kid == "" {
		return nil, false
	}
	for _, k := range m.GetPublicKeys() {
		if k.GetKid() == kid {
			return k, true
		}
	}
	return nil, false
}

// PublicKey decodes a JWK's x parameter into an ed25519.PublicKey. The wire
// encoding is base64url without padding of the raw 32-byte key (RFC 8037).
func PublicKey(k *Key) (ed25519.PublicKey, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil key", ErrSchemaInvalid)
	}
	pub, err := DecodeEd25519X(k.GetX())
	if err != nil {
		return nil, fmt.Errorf("%w (kid %q)", err, k.GetKid())
	}
	return pub, nil
}

// keyActiveAt reports whether k's [not_before, not_after) window covers now.
func keyActiveAt(k *Key, now time.Time) bool {
	notBefore, err := time.Parse(time.RFC3339, k.GetNotBefore())
	if err != nil {
		return false
	}
	notAfter, err := time.Parse(time.RFC3339, k.GetNotAfter())
	if err != nil {
		return false
	}
	return !now.Before(notBefore) && now.Before(notAfter)
}

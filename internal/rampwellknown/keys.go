package rampwellknown

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
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

// DecodeJWKEd25519 is the single guard+decode for a JWK Set entry across every
// JWKS ingestion path (the httpsig bootstrap resolver, the Broker key registry):
// it rejects a non-OKP/Ed25519 key type and decodes the `x` parameter. A wrong
// kty/crv or an undecodable x is ErrSchemaInvalid, so a loader filtering a mixed
// JWK set skips a bad entry uniformly on error rather than re-deriving the
// decode+guard (and drifting on its failure policy) at each call site.
func DecodeJWKEd25519(kty, crv, x string) (ed25519.PublicKey, error) {
	if kty != "OKP" || crv != "Ed25519" {
		return nil, fmt.Errorf("%w: kty=%q crv=%q, want OKP/Ed25519", ErrSchemaInvalid, kty, crv)
	}
	return DecodeEd25519X(x)
}

// NewKey builds a published JWK for an Ed25519 public key valid over the
// half-open window [notBefore, notAfter). Producers use this so every role
// emits an identical JWK shape (RFC 8037: kty=OKP, crv=Ed25519, use=sig,
// alg=EdDSA, x=base64url(pub)). Keys carry no kid: they are identified by their
// RFC 7638 thumbprint (see Thumbprint), which is the RFC 9421 keyid.
func NewKey(pub ed25519.PublicKey, notBefore, notAfter time.Time) *Key {
	// Delegate to KeyFromEncodedX so the RFC 8037 JWK header quartet
	// (kty/crv/use/alg) is stamped in exactly one place.
	return KeyFromEncodedX(
		EncodeEd25519X(pub),
		notBefore.UTC().Format(time.RFC3339),
		notAfter.UTC().Format(time.RFC3339),
	)
}

// KeyFromEncodedX builds a published JWK from an already-base64url x parameter
// (RFC 8037 raw 32-byte public key) and pre-formatted RFC 3339 validity bounds.
// Use it when the key bytes are already encoded — e.g. folding a registry JWKS
// into a WBA directory; reach for NewKey instead when the key is a raw
// ed25519.PublicKey.
func KeyFromEncodedX(x, notBefore, notAfter string) *Key {
	return &Key{
		Kty:       "OKP",
		Crv:       "Ed25519",
		Use:       "sig",
		Alg:       "EdDSA",
		X:         x,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
}

// ActiveKeys returns the WBA directory's keys whose validity window covers now,
// preserving document order. The window is half-open: a key is active when
// not_before <= now < not_after (lower bound inclusive, upper bound strict),
// matching the proto contract and avoiding a double-active instant at rotation.
// Keys with unparseable timestamps are skipped, not fatal.
func ActiveKeys(f *WBAFile, now time.Time) []*Key {
	if f == nil {
		return nil
	}
	active := make([]*Key, 0, len(f.GetKeys()))
	for _, k := range f.GetKeys() {
		if keyActiveAt(k, now) {
			active = append(active, k)
		}
	}
	return active
}

// Window-active offer/agent key selection (the by-domain-anchor "current key"
// selector) now lives in the SDK: resolvers.ActiveEd25519Key /
// ActiveEd25519KeyWithExpiry. Callers use those directly; the in-repo copies were
// retired once the SDK shipped the same selection with its own parity corpus.

// KeyByThumbprint returns the key in f whose RFC 7638 thumbprint equals
// thumbprint (the RFC 9421 keyid) and whether it was found. Each key's
// thumbprint is computed locally from its decoded public key via the SDK thumbprint helper;
// keys with an undecodable `x` are skipped. This is the resolution primitive
// that replaces kid matching after the WBA split.
func KeyByThumbprint(f *WBAFile, thumbprint string) (*Key, bool) {
	if f == nil || thumbprint == "" {
		return nil, false
	}
	for _, k := range f.GetKeys() {
		tp, err := Thumbprint(k)
		if err != nil {
			continue
		}
		if tp == thumbprint {
			return k, true
		}
	}
	return nil, false
}

// Thumbprint returns the RFC 7638 JWK thumbprint (base64url-no-pad, the RFC 9421
// keyid) of k, computed from its decoded Ed25519 public key. A malformed `x`
// yields the decode error from PublicKey.
func Thumbprint(k *Key) (string, error) {
	pub, err := PublicKey(k)
	if err != nil {
		return "", err
	}
	return helpers.Thumbprint(pub)
}

// PublicKey decodes a JWK's x parameter into an ed25519.PublicKey. The wire
// encoding is base64url without padding of the raw 32-byte key (RFC 8037).
func PublicKey(k *Key) (ed25519.PublicKey, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil key", ErrSchemaInvalid)
	}
	return DecodeEd25519X(k.GetX())
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

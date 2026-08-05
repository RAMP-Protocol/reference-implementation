package transport

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

// KeyRegistry holds the Broker's OWN published public keys (today: the relay
// key), fixed at construction. There is no file seeding and no mutation after
// boot: every OTHER participant's key is learned via well-known discovery,
// never registered here — a participant's directory publishes that
// participant's keys only. The served WBA directory is built from this one
// view (see brokerKeySource in wellknown.go); validity windows are not stored
// here — every published window is stamped from the signer clock at each
// document build.
type KeyRegistry struct {
	keys []ed25519.PublicKey
}

// NewKeyRegistry builds the registry from the Broker's own public keys. Every
// key must be a full-size Ed25519 public key — a malformed entry is a wiring
// bug at the composition root, so it fails construction loudly rather than
// being skipped or published broken. The key BYTES are copied in: a caller
// that keeps the slice it passed cannot alter the published key set after
// boot.
func NewKeyRegistry(keys ...ed25519.PublicKey) (*KeyRegistry, error) {
	out := &KeyRegistry{keys: make([]ed25519.PublicKey, len(keys))}
	for i, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("transport: own key %d: %d-byte public key, want %d", i, len(k), ed25519.PublicKeySize)
		}
		out.keys[i] = ed25519.PublicKey(bytes.Clone(k))
	}
	return out, nil
}

// Keys returns the registered keys, in registration order. Each key is a byte
// copy — mutating a returned slice cannot reach the registry's own state.
func (r *KeyRegistry) Keys() []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, len(r.keys))
	for i, k := range r.keys {
		out[i] = ed25519.PublicKey(bytes.Clone(k))
	}
	return out
}

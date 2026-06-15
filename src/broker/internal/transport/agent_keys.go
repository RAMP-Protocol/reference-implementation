package transport

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// KeyEntry mirrors one JWK record in the Broker's on-disk key registry file
// (BROKER_KEYS_FILE). One file carries every RFC 9421 pubkey the Broker serves —
// agent caller keys AND the Broker's own relay key. The kid prefix ("agent." vs
// "broker.") disambiguates purpose; verifiers care only about cryptographic
// identity, not the role label. These entries are folded into the unified
// WellKnownManifest.public_keys served at /.well-known/ramp.json; this struct is
// the loader's file format, not the served wire shape.
type KeyEntry struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// KeysDocument is the JSON shape of the Broker's on-disk key registry file
// (BROKER_KEYS_FILE) — the source the unified WellKnownManifest public_keys list
// is built from, not itself the document served at /.well-known/ramp.json.
type KeysDocument struct {
	Keys []KeyEntry `json:"keys"`
}

// KeyRegistry holds the current set of registered public keys (agents +
// Broker relay). Seeded from disk at boot; future revisions will wire a
// dynamic registration API (v1 demo scope: hardcoded file + in-process
// additions for the relay kid).
type KeyRegistry struct {
	mu   sync.RWMutex
	doc  KeysDocument
	keys map[string]ed25519.PublicKey
}

// NewKeyRegistry returns an empty registry.
func NewKeyRegistry() *KeyRegistry {
	return &KeyRegistry{keys: map[string]ed25519.PublicKey{}}
}

// LoadFile replaces the registry content with the document at path. Malformed
// entries are skipped so a typo can't wedge the Broker at boot; callers may
// inspect err for diagnostic purposes.
func (r *KeyRegistry) LoadFile(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return fmt.Errorf("ramp.json: read %s: %w", path, err)
	}
	return r.LoadBytes(data)
}

// LoadBytes parses raw and replaces the registry content. Empty keys or bad
// base64url values are skipped.
func (r *KeyRegistry) LoadBytes(raw []byte) error {
	var doc KeysDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("ramp.json: decode: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" || k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue
		}
		// Shared "32-byte Ed25519 x" decode/validate; a malformed entry is
		// skipped (not fatal) so one typo can't wedge the Broker at boot.
		pub, err := rampwellknown.DecodeEd25519X(k.X)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.doc = doc
	r.keys = keys
	return nil
}

// PutPublicKey registers a kid → pub entry in memory and reflects it into
// the served JWKS document. Used by the Broker to publish its own relay
// pubkey alongside agent keys loaded from disk.
func (r *KeyRegistry) PutPublicKey(kid string, pub ed25519.PublicKey) {
	if kid == "" || len(pub) != ed25519.PublicKeySize {
		return
	}
	entry := KeyEntry{
		Kid: kid,
		Kty: "OKP",
		Crv: "Ed25519",
		X:   rampwellknown.EncodeEd25519X(pub),
		Use: "sig",
		Alg: "EdDSA",
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[kid] = pub
	filtered := make([]KeyEntry, 0, len(r.doc.Keys)+1)
	for _, k := range r.doc.Keys {
		if k.Kid == kid {
			continue
		}
		filtered = append(filtered, k)
	}
	filtered = append(filtered, entry)
	r.doc.Keys = filtered
}

// Lookup returns the registered pubkey for kid, or (_, false) if unknown.
func (r *KeyRegistry) Lookup(kid string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pub, ok := r.keys[kid]
	return pub, ok
}

// Snapshot returns the current keys as an ed25519-pubkey map. The caller
// receives a copy so subsequent registry mutations do not leak into their
// view.
func (r *KeyRegistry) Snapshot() map[string]ed25519.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]ed25519.PublicKey, len(r.keys))
	for k, v := range r.keys {
		out[k] = v
	}
	return out
}

// Document returns a copy of the public JWKS document. The unified
// /.well-known/ramp.json handler reads this view to embed the agent-key
// registry inside the WellKnownManifest public_keys list.
func (r *KeyRegistry) Document() KeysDocument {
	r.mu.RLock()
	defer r.mu.RUnlock()
	copied := KeysDocument{Keys: make([]KeyEntry, len(r.doc.Keys))}
	copy(copied.Keys, r.doc.Keys)
	return copied
}

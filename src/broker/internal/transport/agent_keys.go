package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sync"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// KeyEntry mirrors one JWK record in the Broker's on-disk key registry file
// (BROKER_KEYS_FILE). One file carries every RFC 9421 pubkey the Broker serves —
// agent caller keys AND the Broker's own relay key. After the WBA split keys
// carry no kid: identity is the RFC 7638 thumbprint of the key, and role is the
// DB requester_type discriminator, not a kid prefix. These entries are folded
// into the WBA directory served at /.well-known/http-message-signatures-directory;
// this struct is the loader's file format, not the served wire shape.
type KeyEntry struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	// NotBefore/NotAfter are the optional RAMP validity window (RFC 3339). An
	// entry carrying one is held to the same not_before/not_after gate as a
	// directory-published key; an entry with a present-but-unparseable
	// window is skipped (fail-closed). Emitted only when set so a windowless key
	// keeps its current served WBA-directory shape.
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

// KeysDocument is the JSON shape of the Broker's on-disk key registry file
// (BROKER_KEYS_FILE) — the source the WBA directory's key set is built from, not
// itself the document served at the WBA path.
type KeysDocument struct {
	Keys []KeyEntry `json:"keys"`
}

// KeyRegistry holds the current set of registered public keys (agents +
// Broker relay), keyed by RFC 7638 thumbprint (the RFC 9421 keyid). Seeded from
// disk at boot; future revisions will wire a dynamic registration API (v1 demo
// scope: hardcoded file + in-process additions for the relay key).
type KeyRegistry struct {
	mu      sync.RWMutex
	doc     KeysDocument
	keys    map[string]ed25519.PublicKey
	windows map[string]keyWindow
}

// keyWindow is the optional half-open validity window [notBefore, notAfter) for
// a registered key. A zero bound is unbounded on that side.
type keyWindow struct {
	notBefore time.Time
	notAfter  time.Time
}

// NewKeyRegistry returns an empty registry.
func NewKeyRegistry() *KeyRegistry {
	return &KeyRegistry{keys: map[string]ed25519.PublicKey{}, windows: map[string]keyWindow{}}
}

// LoadFile replaces the registry content with the document at path. Malformed
// entries are skipped so a typo can't wedge the Broker at boot; callers may
// inspect err for diagnostic purposes.
func (r *KeyRegistry) LoadFile(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return fmt.Errorf("broker keys: read %s: %w", path, err)
	}
	return r.LoadBytes(data)
}

// LoadBytes parses raw and replaces the registry content. Empty keys or bad
// base64url values are skipped. Each key is indexed by its RFC 7638 thumbprint.
func (r *KeyRegistry) LoadBytes(raw []byte) error {
	var doc KeysDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("broker keys: decode: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(doc.Keys))
	windows := make(map[string]keyWindow, len(doc.Keys))
	// Build the trust maps through the shared fail-closed loader (the same one
	// the Exchange uses); a malformed or non-Ed25519 entry is skipped (not fatal)
	// so one typo can't wedge the Broker at boot. The richer doc parsed above is
	// retained separately to rebuild the served WBA directory (use/alg), which the
	// trust maps do not carry — hence the two views of the same bytes.
	if err := keypolicy.LoadJWKSBytes(raw, func(tk keypolicy.TimedKey) {
		keys[tk.Thumbprint] = tk.Public
		windows[tk.Thumbprint] = keyWindow{notBefore: tk.NotBefore, notAfter: tk.NotAfter}
	}); err != nil {
		return fmt.Errorf("broker keys: decode: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.doc = doc
	r.keys = keys
	r.windows = windows
	return nil
}

// PutPublicKey registers pub in memory (keyed by its RFC 7638 thumbprint) and
// reflects it into the served WBA key set. Used by the Broker to publish its own
// relay pubkey alongside agent keys loaded from disk.
func (r *KeyRegistry) PutPublicKey(pub ed25519.PublicKey) {
	if len(pub) != ed25519.PublicKeySize {
		return
	}
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		return
	}
	x := rampwellknown.EncodeEd25519X(pub)
	entry := KeyEntry{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   x,
		Use: "sig",
		Alg: "EdDSA",
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[tp] = pub
	r.windows[tp] = keyWindow{} // the Broker's own relay key is unbounded
	filtered := make([]KeyEntry, 0, len(r.doc.Keys)+1)
	for _, k := range r.doc.Keys {
		if k.X == x {
			continue
		}
		filtered = append(filtered, k)
	}
	filtered = append(filtered, entry)
	r.doc.Keys = filtered
}

// Lookup returns the registered pubkey for keyid (a thumbprint), or (_, false).
func (r *KeyRegistry) Lookup(keyid string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pub, ok := r.keys[keyid]
	return pub, ok
}

// Resolve implements helpers.KeyResolver over the live registry. Unlike the
// frozen snapshot the inbound middleware wraps, this view reflects keys
// registered after boot — used by the relay handler to verify agent
// signatures (sig1) before forwarding to the Exchange.
func (r *KeyRegistry) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	pub, ok := r.Lookup(keyID)
	if !ok {
		return nil, fmt.Errorf("%w: keyid=%q", helpers.ErrUnknownKey, keyID)
	}
	return pub, nil
}

// WindowedResolver returns a helpers.KeyResolver over a frozen snapshot of the
// registry that enforces each key's not_before/not_after validity window
// against clk: a key resolved outside its window yields resolvers.ErrKeyExpired
// (an authoritative negative — a CompositeResolver halts rather than falling
// through), restoring the static-bootstrap gate that the SDK's
// window-blind helpers.StaticKeyResolver does not provide. Like Snapshot, the
// resolver is a point-in-time copy; keys registered after this call are not
// reflected.
func (r *KeyRegistry) WindowedResolver(clk clock.Clock) helpers.KeyResolver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	resolver := keypolicy.NewTimedStaticResolver(clk)
	for tp, pub := range r.keys {
		w := r.windows[tp]
		resolver.PutTimed(tp, pub, w.notBefore, w.notAfter)
	}
	return resolver
}

// Snapshot returns the current keys as a thumbprint→pubkey map. The caller
// receives a copy so subsequent registry mutations do not leak into their view.
func (r *KeyRegistry) Snapshot() map[string]ed25519.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]ed25519.PublicKey, len(r.keys))
	maps.Copy(out, r.keys)
	return out
}

// Document returns a copy of the registry's JWK document. The WBA directory
// handler reads this view to embed the agent-key registry in the served key set.
func (r *KeyRegistry) Document() KeysDocument {
	r.mu.RLock()
	defer r.mu.RUnlock()
	copied := KeysDocument{Keys: make([]KeyEntry, len(r.doc.Keys))}
	copy(copied.Keys, r.doc.Keys)
	return copied
}

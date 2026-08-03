package httpsig

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// KeyResolver looks up the Ed25519 public key registered for keyid (after the
// WBA split, an RFC 7638 thumbprint). The adapter is the boundary between the
// RFC 9421 verifier and whatever key directory the caller wires (static map,
// Broker WBA directory, per-agent discovery). Implementations are expected to
// return ErrUnknownKey (or a wrapping error) when the keyid is not registered.
// A discovery resolver reads the signed directory origin via
// SignatureAgentFromContext to know which WBA directory to fetch.
type KeyResolver interface {
	Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error)
}

type signatureAgentCtxKey struct{}

// WithSignatureAgent returns ctx carrying the (signed) Signature-Agent directory
// origin. The verifier sets it before invoking a KeyResolver so a discovery
// resolver knows which WBA directory to fetch and match the keyid against.
func WithSignatureAgent(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, signatureAgentCtxKey{}, dir)
}

// SignatureAgentFromContext returns the Signature-Agent directory origin set by
// the verifier, or "" when absent.
func SignatureAgentFromContext(ctx context.Context) string {
	v, _ := ctx.Value(signatureAgentCtxKey{}).(string)
	return v
}

// StaticResolver serves pubkeys from an in-memory map. Tests and the demo
// hardcoded-agent path use this directly. A key MAY carry a half-open validity
// window (not_before/not_after); a key outside its window resolves to
// ErrKeyExpired, so a statically-loaded key is held to the same validity gate as
// a directory-published one (closing the gap where a static bootstrap key
// bypassed not_before/not_after). A key with no window is unbounded.
type StaticResolver struct {
	mu   sync.RWMutex
	keys map[string]staticKey
	now  func() time.Time
}

// staticKey is a pubkey plus an optional half-open validity window. A zero
// notBefore/notAfter is unbounded on that side.
type staticKey struct {
	pub       ed25519.PublicKey
	notBefore time.Time
	notAfter  time.Time
}

func (k staticKey) activeAt(t time.Time) bool {
	if !k.notBefore.IsZero() && t.Before(k.notBefore) {
		return false
	}
	if !k.notAfter.IsZero() && !t.Before(k.notAfter) {
		return false
	}
	return true
}

// NewStaticResolver returns a StaticResolver seeded with keys, each unbounded
// (always valid). The validity clock defaults to time.Now; SetClock overrides it.
func NewStaticResolver(keys map[string]ed25519.PublicKey) *StaticResolver {
	copied := make(map[string]staticKey, len(keys))
	for k, v := range keys {
		copied[k] = staticKey{pub: v}
	}
	return &StaticResolver{keys: copied, now: clock.System{}.Now}
}

// SetClock overrides the validity clock (deterministic time in tests).
func (s *StaticResolver) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Resolve implements KeyResolver. A known key outside its validity window
// resolves to ErrKeyExpired (authoritative — the composite must not fall through).
func (s *StaticResolver) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: keyid=%q", ErrUnknownKey, keyID)
	}
	if !k.activeAt(s.now()) {
		return nil, fmt.Errorf("%w: keyid=%q", ErrKeyExpired, keyID)
	}
	return k.pub, nil
}

// Put registers a keyid → pubkey mapping with no validity window (always valid).
// Intended for test seeding and dynamic registration paths (Broker
// agent-register endpoint).
func (s *StaticResolver) Put(keyID string, pub ed25519.PublicKey) {
	s.PutTimed(keyID, pub, time.Time{}, time.Time{})
}

// PutTimed registers a keyid → pubkey mapping bounded by a half-open validity
// window [notBefore, notAfter). A zero bound is unbounded on that side.
func (s *StaticResolver) PutTimed(keyID string, pub ed25519.PublicKey, notBefore, notAfter time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[keyID] = staticKey{pub: pub, notBefore: notBefore, notAfter: notAfter}
}

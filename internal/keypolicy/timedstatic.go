package keypolicy

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// TimedStaticResolver serves Ed25519 public keys from an in-memory map, each
// optionally bounded by a half-open validity window [notBefore, notAfter). It
// restores the static-bootstrap validity gate the SDK's
// helpers.StaticKeyResolver (Put only, no window) does not provide: a key
// resolved outside its window yields resolvers.ErrKeyExpired — an AUTHORITATIVE
// negative, so a CompositeResolver rejects rather than falling through to a
// later, more permissive delegate. A key with no window is unbounded (the
// current bootstrap keys are unchanged).
//
// Window-on-static is app policy (like the composite fail-closed ordering),
// so it lives here rather than in the SDK; all methods operate over the
// helpers.KeyResolver interface the rest of the app already consumes.
type TimedStaticResolver struct {
	mu   sync.RWMutex
	keys map[string]timedKey
	clk  clock.Clock
}

// timedKey is a pubkey plus an optional half-open validity window. A zero
// notBefore/notAfter is unbounded on that side.
type timedKey struct {
	pub       ed25519.PublicKey
	notBefore time.Time
	notAfter  time.Time
}

func (k timedKey) activeAt(t time.Time) bool {
	if !k.notBefore.IsZero() && t.Before(k.notBefore) {
		return false
	}
	if !k.notAfter.IsZero() && !t.Before(k.notAfter) {
		return false
	}
	return true
}

// NewTimedStaticResolver returns an empty resolver reading validity windows
// against clk (clock.System in production, a DeterministicClock in tests). A
// nil clk defaults to clock.System so callers that do not care about
// determinism can pass nil.
func NewTimedStaticResolver(clk clock.Clock) *TimedStaticResolver {
	if clk == nil {
		clk = clock.System{}
	}
	return &TimedStaticResolver{keys: map[string]timedKey{}, clk: clk}
}

// Put registers keyID → pub with no validity window (always valid). It is the
// drop-in replacement for helpers.StaticKeyResolver.Put.
func (r *TimedStaticResolver) Put(keyID string, pub ed25519.PublicKey) {
	r.PutTimed(keyID, pub, time.Time{}, time.Time{})
}

// PutTimed registers keyID → pub bounded by the half-open window
// [notBefore, notAfter). A zero bound is unbounded on that side.
func (r *TimedStaticResolver) PutTimed(keyID string, pub ed25519.PublicKey, notBefore, notAfter time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[keyID] = timedKey{pub: pub, notBefore: notBefore, notAfter: notAfter}
}

// Resolve implements helpers.KeyResolver. An unknown keyID yields
// helpers.ErrUnknownKey (the composite falls through to the next delegate); a
// known key outside its validity window yields resolvers.ErrKeyExpired (the
// composite halts — the negative is authoritative).
func (r *TimedStaticResolver) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: keyid=%q", helpers.ErrUnknownKey, keyID)
	}
	if !k.activeAt(r.clk.Now()) {
		return nil, fmt.Errorf("%w: keyid=%q", resolvers.ErrKeyExpired, keyID)
	}
	return k.pub, nil
}

// ParseWindow parses optional RFC 3339 not_before / not_after bounds. An empty
// string is unbounded (zero time). A present-but-unparseable bound reports
// ok=false so the caller skips the malformed entry rather than treating a typo
// as unbounded — which would make an out-of-window key silently always-valid
// (fail-closed).
func ParseWindow(notBefore, notAfter string) (nb, na time.Time, ok bool) {
	var err error
	if notBefore != "" {
		if nb, err = time.Parse(time.RFC3339, notBefore); err != nil {
			return time.Time{}, time.Time{}, false
		}
	}
	if notAfter != "" {
		if na, err = time.Parse(time.RFC3339, notAfter); err != nil {
			return time.Time{}, time.Time{}, false
		}
	}
	return nb, na, true
}

// Package transporttest holds test fixtures shared between the broker
// transport tests and the cmd/server wiring tests, so each construction rule
// (registry validation, the never-resolves inbound delegate) has one home:
// test fixtures are shared, not copy-pasted, and a future change to
// NewKeyRegistry's validation is one edit here instead of one per test file.
package transporttest

import (
	"crypto/ed25519"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
)

// MustRegistry builds an own-key registry — empty when called with no keys,
// the shape the minimal wiring tests use — failing the test on a constructor
// rejection, which only a malformed fixture key can cause.
func MustRegistry(tb testing.TB, keys ...ed25519.PublicKey) *transport.KeyRegistry {
	tb.Helper()
	reg, err := transport.NewKeyRegistry(keys...)
	if err != nil {
		tb.Fatalf("own-key registry: %v", err)
	}
	return reg
}

// NeverResolves is the explicit inbound key resolver for tests that never
// present a signature: every kid reports unknown. The broker mux requires a
// non-nil resolver, so minimal wiring tests pass this instead of leaving the
// field unset. The SDK's empty static resolver already misses with
// helpers.ErrUnknownKey and the keyid wrapped in — the same shape every
// production resolver miss has — so this is a named intent, not a hand-written
// double.
func NeverResolves() helpers.KeyResolver {
	return helpers.NewStaticKeyResolver(nil)
}

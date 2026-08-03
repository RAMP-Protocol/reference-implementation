package transport

import (
	"context"
	"errors"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy/windowtest"
)

// TestKeyRegistry_WindowBehavior wires the Broker's KeyRegistry into the shared
// static-key validity-window table (windowtest.BehaviorCases): LoadBytes +
// WindowedResolver must honour the [not_before, not_after) gate — a lapsed or
// not-yet-valid key resolves to ErrKeyExpired (authoritative, not the
// window-blind unconditional verify the pre-SDK helpers.StaticKeyResolver gave),
// an in-window key resolves to its pubkey.
func TestKeyRegistry_WindowBehavior(t *testing.T) {
	windowtest.RunBehavior(t, func(t *testing.T, raw []byte, tp string) error {
		reg := NewKeyRegistry()
		if err := reg.LoadBytes(raw); err != nil {
			t.Fatalf("LoadBytes: %v", err)
		}
		_, err := reg.WindowedResolver(clock.NewDeterministic(windowtest.Anchor)).
			Resolve(context.Background(), tp)
		return err
	})
}

// TestKeyRegistry_UnparseableWindowSkipped is the Broker-specific fail-closed
// outcome (not shared, because the loaders diverge here): a present-but-
// unparseable window makes the entry malformed, so LoadBytes skips it entirely
// (never loaded as unbounded) and the thumbprint stays unknown — the composite
// falls through to ErrUnknownKey rather than serving the key.
func TestKeyRegistry_UnparseableWindowSkipped(t *testing.T) {
	raw, tp := windowtest.MintWindowedJWKS(t, "", "not-a-timestamp")
	reg := NewKeyRegistry()
	if err := reg.LoadBytes(raw); err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if _, ok := reg.Lookup(tp); ok {
		t.Fatal("entry with unparseable window must be skipped, not loaded as unbounded")
	}
	if _, err := reg.WindowedResolver(clock.System{}).Resolve(context.Background(), tp); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("skipped entry must be unknown, got %v", err)
	}
}

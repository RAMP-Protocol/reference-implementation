//go:build integration

package lifecycle_test

import (
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/lifecycle"
)

// The scheduler suite drives RunOnce over a deterministic clock against a real Vault,
// asserting the rotation state machine through the production custody surface
// (List/Active/Signer): both keys during the overlap, only the fresh key after the
// retired one is pruned. Reuses fakeInvalidator from the unit suite (same package).
const (
	schedSub     = "agent-1.rampmcp.org"
	schedPeriod  = 10 * time.Hour
	schedOverlap = 2 * time.Hour
)

// longWindow opens at the anchor and stays open well past a rotation period, so the
// scheduler's Expire has a window to actually shorten — a sign-up key need not be
// minted with exactly the rotation lifetime.
func longWindow() keystore.Window {
	return keystore.Window{NotBefore: schedAnchor, NotAfter: schedAnchor.Add(100 * time.Hour)}
}

func newScheduler(store *keystore.VaultStore, inv *fakeInvalidator, clk clock.Clock) *lifecycle.Scheduler {
	return lifecycle.NewScheduler(store, inv, clk, testutil.DiscardLogger(), lifecycle.SchedulerConfig{
		Period: schedPeriod, Overlap: schedOverlap,
	})
}

// When the newest key reaches the rotation period, a fresh overlapping key is minted,
// the outgoing key is shortened to now+overlap (both verify during the overlap), and
// only the newest signs.
func TestScheduler_RotatesAnOverlappingKeyWhenDue(t *testing.T) {
	store, clk := newRotationStore(t)
	ctx := t.Context()
	inv := &fakeInvalidator{}

	orig, err := store.Create(ctx, schedSub, longWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	clk.Advance(schedPeriod) // the newest key is now exactly `period` old → due
	newScheduler(store, inv, clk).RunOnce(ctx)

	keys, err := store.List(ctx, schedSub)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("after rotation: %d keys, want 2 (overlap)", len(keys))
	}

	now := schedAnchor.Add(schedPeriod)
	var old *keystore.Key
	for i := range keys {
		if keys[i].Ref.Thumbprint == orig.Ref.Thumbprint {
			old = &keys[i]
		}
	}
	if old == nil {
		t.Fatal("the original key vanished from the overlap")
	}
	if !old.Window.NotAfter.Equal(now.Add(schedOverlap)) {
		t.Errorf("outgoing key not_after = %s, want now+overlap %s", old.Window.NotAfter, now.Add(schedOverlap))
	}

	active, err := store.Active(ctx, schedSub)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.Ref.Thumbprint == orig.Ref.Thumbprint {
		t.Error("Active still returns the outgoing key, want the freshly minted one")
	}
	// A rotation pass invalidates after the mint and again after the overlap shorten,
	// so one-or-more calls is expected; every call must name this subdomain.
	if len(inv.calls) == 0 {
		t.Error("rotation did not invalidate the cache")
	}
	for _, c := range inv.calls {
		if c != schedSub {
			t.Errorf("invalidator called for %q, want only %q", c, schedSub)
		}
	}
}

// Before the period elapses nothing rotates and the cache is left alone.
func TestScheduler_LeavesKeysAloneBeforeDue(t *testing.T) {
	store, clk := newRotationStore(t)
	ctx := t.Context()
	inv := &fakeInvalidator{}

	if _, err := store.Create(ctx, schedSub, longWindow()); err != nil {
		t.Fatalf("create: %v", err)
	}
	clk.Advance(schedPeriod - time.Hour) // not yet due
	newScheduler(store, inv, clk).RunOnce(ctx)

	keys, err := store.List(ctx, schedSub)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("rotated early: %d keys, want 1", len(keys))
	}
	if len(inv.calls) != 0 {
		t.Errorf("invalidated without rotating: %v", inv.calls)
	}
}

// Once a retired key's window has closed (plus the prune grace), a later pass erases
// its material, leaving only the fresh key.
func TestScheduler_PrunesRetiredKeysAfterTheirWindowCloses(t *testing.T) {
	store, clk := newRotationStore(t)
	ctx := t.Context()
	inv := &fakeInvalidator{}
	sched := newScheduler(store, inv, clk)

	orig, err := store.Create(ctx, schedSub, longWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	clk.Advance(schedPeriod)
	sched.RunOnce(ctx) // rotate: the outgoing key now closes at anchor+period+overlap

	clk.Advance(schedOverlap + 2*time.Hour) // past the outgoing key's close + the prune grace
	sched.RunOnce(ctx)

	keys, err := store.List(ctx, schedSub)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("after prune: %d keys, want 1 (only the survivor)", len(keys))
	}
	if keys[0].Ref.Thumbprint == orig.Ref.Thumbprint {
		t.Error("prune kept the retired original instead of the fresh key")
	}
	if _, err := store.Signer(ctx, orig.Ref); err == nil {
		t.Error("the pruned key can still sign; its material was not destroyed")
	}
}

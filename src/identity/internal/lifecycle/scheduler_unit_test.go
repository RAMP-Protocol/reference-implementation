package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/lifecycle"
)

// These unit tests drive RunOnce over a stateful fake with injectable per-operation
// errors — the scheduler's failure branches, which a real Vault cannot be made to
// exhibit on demand, and which the integration suite (happy paths only) never reaches.
// Names are prefixed to avoid colliding with the integration suite in the same package.

const (
	uSub     = "agent-x.rampmcp.org"
	uPeriod  = 10 * time.Hour
	uOverlap = 2 * time.Hour
)

var uAnchor = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

// fakeRotationStore is an in-memory RotationKeyStore: Create appends, Expire shortens,
// Destroy removes, List returns newest-first. Any operation can be made to fail by
// setting the matching error field, which the tests toggle between passes.
type fakeRotationStore struct {
	clk     clock.Clock
	keys    map[string][]keystore.Key
	counter int

	listSubErr error
	listErr    error
	createErr  error
	expireErr  error
	destroyErr error

	createCalls int
}

func newFakeRotationStore(clk clock.Clock) *fakeRotationStore {
	return &fakeRotationStore{clk: clk, keys: map[string][]keystore.Key{}}
}

func (f *fakeRotationStore) ListSubdomains(context.Context) ([]string, error) {
	if f.listSubErr != nil {
		return nil, f.listSubErr
	}
	out := make([]string, 0, len(f.keys))
	for sub := range f.keys {
		out = append(out, sub)
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeRotationStore) List(_ context.Context, sub string) ([]keystore.Key, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	ks := append([]keystore.Key(nil), f.keys[sub]...)
	sort.SliceStable(ks, func(i, j int) bool {
		if !ks[i].CreatedAt.Equal(ks[j].CreatedAt) {
			return ks[i].CreatedAt.After(ks[j].CreatedAt) // newest first
		}
		return ks[i].Ref.Thumbprint < ks[j].Ref.Thumbprint
	})
	return ks, nil
}

func (f *fakeRotationStore) Create(_ context.Context, sub string, w keystore.Window) (keystore.Key, error) {
	f.createCalls++
	if f.createErr != nil {
		return keystore.Key{}, f.createErr
	}
	f.counter++
	k := keystore.Key{
		Ref:       keystore.Ref{Subdomain: sub, Thumbprint: fmt.Sprintf("tp-%03d", f.counter)},
		Window:    w,
		CreatedAt: f.clk.Now(),
	}
	f.keys[sub] = append(f.keys[sub], k)
	return k, nil
}

func (f *fakeRotationStore) Expire(_ context.Context, ref keystore.Ref, notAfter time.Time) error {
	if f.expireErr != nil {
		return f.expireErr
	}
	for i, k := range f.keys[ref.Subdomain] {
		if k.Ref == ref {
			f.keys[ref.Subdomain][i].Window.NotAfter = notAfter
			return nil
		}
	}
	return nil
}

func (f *fakeRotationStore) Destroy(_ context.Context, ref keystore.Ref) error {
	if f.destroyErr != nil {
		return f.destroyErr
	}
	ks := f.keys[ref.Subdomain]
	for i, k := range ks {
		if k.Ref == ref {
			f.keys[ref.Subdomain] = append(ks[:i], ks[i+1:]...)
			return nil
		}
	}
	return nil
}

func newUnitScheduler(store lifecycle.RotationKeyStore, inv *fakeInvalidator, clk clock.Clock) *lifecycle.Scheduler {
	return lifecycle.NewScheduler(store, inv, clk, testutil.DiscardLogger(),
		lifecycle.SchedulerConfig{Period: uPeriod, Overlap: uOverlap})
}

func findKey(t *testing.T, store *fakeRotationStore, sub, thumbprint string) keystore.Key {
	t.Helper()
	ks, err := store.List(context.Background(), sub)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, k := range ks {
		if k.Ref.Thumbprint == thumbprint {
			return k
		}
	}
	t.Fatalf("key %s not found for %s", thumbprint, sub)
	return keystore.Key{}
}

// A ListSubdomains failure ends the pass cleanly — no agent is processed, nothing is
// minted or invalidated.
func TestScheduler_ListSubdomainsErrorEndsThePass(t *testing.T) {
	clk := clock.NewDeterministic(uAnchor)
	store := newFakeRotationStore(clk)
	store.keys[uSub] = []keystore.Key{{ // a due key that would rotate if the pass ran
		Ref: keystore.Ref{Subdomain: uSub, Thumbprint: "tp-old"}, CreatedAt: uAnchor,
		Window: keystore.Window{NotBefore: uAnchor, NotAfter: uAnchor.Add(100 * time.Hour)},
	}}
	store.listSubErr = errors.New("vault down")
	inv := &fakeInvalidator{}
	clk.Advance(uPeriod)

	newUnitScheduler(store, inv, clk).RunOnce(context.Background())

	if store.createCalls != 0 || len(inv.calls) != 0 {
		t.Errorf("a ListSubdomains failure still drove work: creates=%d invalidations=%v", store.createCalls, inv.calls)
	}
}

// A failed mint must not half-apply: no invalidate, and the outgoing key's window is
// left exactly as it was.
func TestScheduler_MintFailureLeavesTheOldKeyUntouched(t *testing.T) {
	clk := clock.NewDeterministic(uAnchor)
	store := newFakeRotationStore(clk)
	store.keys[uSub] = []keystore.Key{{
		Ref: keystore.Ref{Subdomain: uSub, Thumbprint: "tp-old"}, CreatedAt: uAnchor,
		Window: keystore.Window{NotBefore: uAnchor, NotAfter: uAnchor.Add(100 * time.Hour)},
	}}
	store.createErr = errors.New("vault blip")
	inv := &fakeInvalidator{}
	clk.Advance(uPeriod)

	newUnitScheduler(store, inv, clk).RunOnce(context.Background())

	if len(inv.calls) != 0 {
		t.Errorf("invalidated despite a failed mint: %v", inv.calls)
	}
	if got := findKey(t, store, uSub, "tp-old").Window.NotAfter; !got.Equal(uAnchor.Add(100 * time.Hour)) {
		t.Errorf("old key window changed on a failed mint: not_after = %s", got)
	}
}

// The overlap-shorten regression: if the mint lands but the overlap shorten fails (a Vault blip
// between the two writes), the mint still invalidates (the new key must be served) and
// the old key keeps its long window — then the NEXT pass finds it by its window and
// shortens it, without minting again. The rotation self-heals.
func TestScheduler_ExpireFailureSelfHealsOnTheNextPass(t *testing.T) {
	clk := clock.NewDeterministic(uAnchor)
	store := newFakeRotationStore(clk)
	store.keys[uSub] = []keystore.Key{{
		Ref: keystore.Ref{Subdomain: uSub, Thumbprint: "tp-old"}, CreatedAt: uAnchor,
		Window: keystore.Window{NotBefore: uAnchor, NotAfter: uAnchor.Add(100 * time.Hour)},
	}}
	inv := &fakeInvalidator{}
	sched := newUnitScheduler(store, inv, clk)

	// Pass 1: mint succeeds, overlap shorten fails.
	clk.Advance(uPeriod)
	store.expireErr = errors.New("vault blip")
	sched.RunOnce(context.Background())

	if len(inv.calls) == 0 {
		t.Error("a successful mint must invalidate even when the overlap shorten fails")
	}
	if got := findKey(t, store, uSub, "tp-old").Window.NotAfter; !got.Equal(uAnchor.Add(100 * time.Hour)) {
		t.Fatalf("old key was shortened despite the Expire failure: %s", got)
	}

	// Pass 2: Vault recovered. No new mint; the outgoing key is shortened to now+overlap.
	store.expireErr = nil
	clk.Advance(time.Hour)
	mintsBefore := store.createCalls
	sched.RunOnce(context.Background())

	if store.createCalls != mintsBefore {
		t.Error("self-heal pass minted a new key; it should only shorten the outgoing one")
	}
	now2 := uAnchor.Add(uPeriod + time.Hour)
	if got := findKey(t, store, uSub, "tp-old").Window.NotAfter; !got.Equal(now2.Add(uOverlap)) {
		t.Errorf("outgoing key not_after = %s, want now+overlap %s (self-heal did not shorten it)", got, now2.Add(uOverlap))
	}
}

// A Destroy failure during prune is logged and skipped, never fatal — no key is lost.
func TestScheduler_PruneDestroyErrorDoesNotLoseKeys(t *testing.T) {
	clk := clock.NewDeterministic(uAnchor)
	store := newFakeRotationStore(clk)
	// Two keys already past their window (prunable) but younger than the period, so no
	// rotation fires and only prune runs.
	store.keys[uSub] = []keystore.Key{
		{
			Ref: keystore.Ref{Subdomain: uSub, Thumbprint: "tp-a"}, CreatedAt: uAnchor.Add(-4 * time.Hour),
			Window: keystore.Window{NotBefore: uAnchor.Add(-4 * time.Hour), NotAfter: uAnchor.Add(-3 * time.Hour)},
		},
		{
			Ref: keystore.Ref{Subdomain: uSub, Thumbprint: "tp-b"}, CreatedAt: uAnchor.Add(-3 * time.Hour),
			Window: keystore.Window{NotBefore: uAnchor.Add(-3 * time.Hour), NotAfter: uAnchor.Add(-2 * time.Hour)},
		},
	}
	store.destroyErr = errors.New("vault down")
	inv := &fakeInvalidator{}

	newUnitScheduler(store, inv, clk).RunOnce(context.Background())

	if ks, _ := store.List(context.Background(), uSub); len(ks) != 2 {
		t.Errorf("keys = %d after a failed prune, want 2 (a destroy failure must not lose keys)", len(ks))
	}
}

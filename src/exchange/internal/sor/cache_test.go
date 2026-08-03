package sor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// The caching decorator's contract: within the TTL a cached true/false is
// served without touching the inner adapter; past expiry the inner adapter is
// re-read (so an operator's flip in the SoR converges within one TTL); errors
// — ErrAccountNotFound above all — are never cached; OnRegister is a pure
// passthrough that never seeds the cache. All time flows through
// clock.DeterministicClock, so expiry is exercised without sleeping.

// fakeAdapter is a call-counting Adapter stub. Its account set is mutable so
// tests can flip an active flag or make an account appear between calls.
type fakeAdapter struct {
	mu              sync.Mutex
	active          map[string]bool // billing_ref → active; absent = not found
	isActiveCalls   int
	onRegisterCalls int
}

func newFakeAdapter() *fakeAdapter {
	return &fakeAdapter{active: map[string]bool{}}
}

func (f *fakeAdapter) OnRegister(_ context.Context, req OnRegisterRequest) (Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onRegisterCalls++
	return Account{BillingRef: req.BillingRef, Subdomain: req.Subdomain, Active: req.Active}, nil
}

func (f *fakeAdapter) IsActive(_ context.Context, billingRef string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.isActiveCalls++
	if billingRef == "" {
		return false, ErrBillingRefRequired
	}
	active, ok := f.active[billingRef]
	if !ok {
		return false, ErrAccountNotFound
	}
	return active, nil
}

func (f *fakeAdapter) setActive(billingRef string, active bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active[billingRef] = active
}

func (f *fakeAdapter) isActiveCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.isActiveCalls
}

func (f *fakeAdapter) onRegisterCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.onRegisterCalls
}

func testStart() time.Time {
	return time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
}

func mustIsActive(t *testing.T, a Adapter, billingRef string) bool {
	t.Helper()
	active, err := a.IsActive(context.Background(), billingRef)
	if err != nil {
		t.Fatalf("IsActive(%q) error = %v, want nil", billingRef, err)
	}
	return active
}

func TestCachingAdapter_ServesCachedValueWithinTTL(t *testing.T) {
	t.Parallel()
	fake := newFakeAdapter()
	fake.setActive("ref-hit", true)
	clk := clock.NewDeterministic(testStart())
	cached := NewCachingAdapter(fake, 10*time.Second, clk)

	if got := mustIsActive(t, cached, "ref-hit"); !got {
		t.Errorf("first IsActive = %v, want true", got)
	}
	clk.Advance(9 * time.Second)
	if got := mustIsActive(t, cached, "ref-hit"); !got {
		t.Errorf("second IsActive = %v, want true", got)
	}
	if calls := fake.isActiveCallCount(); calls != 1 {
		t.Errorf("inner IsActive calls = %d, want 1 (second read must hit the cache)", calls)
	}
}

func TestCachingAdapter_ReReadsInnerAfterExpiry(t *testing.T) {
	t.Parallel()
	fake := newFakeAdapter()
	fake.setActive("ref-expiry", true)
	clk := clock.NewDeterministic(testStart())
	ttl := 10 * time.Second
	cached := NewCachingAdapter(fake, ttl, clk)

	mustIsActive(t, cached, "ref-expiry")
	clk.Advance(ttl) // expiry is exclusive: at exactly now+ttl the entry is stale
	mustIsActive(t, cached, "ref-expiry")
	if calls := fake.isActiveCallCount(); calls != 2 {
		t.Errorf("inner IsActive calls = %d, want 2 (read past expiry must re-read inner)", calls)
	}
}

func TestCachingAdapter_ConvergesOnFlipWithinOneTTL(t *testing.T) {
	t.Parallel()
	fake := newFakeAdapter()
	fake.setActive("ref-flip", false)
	clk := clock.NewDeterministic(testStart())
	ttl := 10 * time.Second
	cached := NewCachingAdapter(fake, ttl, clk)

	if got := mustIsActive(t, cached, "ref-flip"); got {
		t.Errorf("IsActive before flip = %v, want false", got)
	}

	// Operator activates the account in the SoR; the cached false is served
	// until the entry expires, then the read converges on the new value.
	fake.setActive("ref-flip", true)
	clk.Advance(ttl - time.Second)
	if got := mustIsActive(t, cached, "ref-flip"); got {
		t.Errorf("IsActive within TTL after flip = %v, want false (stale value served)", got)
	}
	if calls := fake.isActiveCallCount(); calls != 1 {
		t.Errorf("inner IsActive calls within TTL = %d, want 1 (stale read must hit the cache)", calls)
	}
	clk.Advance(time.Second)
	if got := mustIsActive(t, cached, "ref-flip"); !got {
		t.Errorf("IsActive past TTL after flip = %v, want true (converged)", got)
	}
	if calls := fake.isActiveCallCount(); calls != 2 {
		t.Errorf("inner IsActive calls past TTL = %d, want 2 (read past expiry must re-read inner)", calls)
	}
}

func TestCachingAdapter_ConvergesOnDeactivationWithinOneTTL(t *testing.T) {
	t.Parallel()
	fake := newFakeAdapter()
	fake.setActive("ref-revoke", true)
	clk := clock.NewDeterministic(testStart())
	ttl := 10 * time.Second
	cached := NewCachingAdapter(fake, ttl, clk)

	if got := mustIsActive(t, cached, "ref-revoke"); !got {
		t.Errorf("IsActive before revocation = %v, want true", got)
	}

	// Operator revokes the account in the SoR; the cached true is served until
	// the entry expires, then the read converges on inactive — the
	// security-relevant direction: a revoked account stays usable for at most
	// one TTL.
	fake.setActive("ref-revoke", false)
	clk.Advance(ttl - time.Second)
	if got := mustIsActive(t, cached, "ref-revoke"); !got {
		t.Errorf("IsActive within TTL after revocation = %v, want true (stale value served)", got)
	}
	if calls := fake.isActiveCallCount(); calls != 1 {
		t.Errorf("inner IsActive calls within TTL = %d, want 1 (stale read must hit the cache)", calls)
	}
	clk.Advance(time.Second)
	if got := mustIsActive(t, cached, "ref-revoke"); got {
		t.Errorf("IsActive past TTL after revocation = %v, want false (converged)", got)
	}
	if calls := fake.isActiveCallCount(); calls != 2 {
		t.Errorf("inner IsActive calls past TTL = %d, want 2 (read past expiry must re-read inner)", calls)
	}
}

func TestCachingAdapter_NotFoundIsNeverCached(t *testing.T) {
	t.Parallel()
	fake := newFakeAdapter()
	clk := clock.NewDeterministic(testStart())
	cached := NewCachingAdapter(fake, 10*time.Second, clk)
	ctx := context.Background()

	for i := range 2 {
		if _, err := cached.IsActive(ctx, "ref-late"); !errors.Is(err, ErrAccountNotFound) {
			t.Fatalf("IsActive call %d error = %v, want ErrAccountNotFound", i+1, err)
		}
	}
	if calls := fake.isActiveCallCount(); calls != 2 {
		t.Errorf("inner IsActive calls = %d, want 2 (not-found must not be cached)", calls)
	}

	// The account appears in the SoR; the very next read sees it (no negative
	// entry to wait out) and the successful result is cached as usual.
	fake.setActive("ref-late", true)
	if got := mustIsActive(t, cached, "ref-late"); !got {
		t.Errorf("IsActive after account appears = %v, want true", got)
	}
	mustIsActive(t, cached, "ref-late")
	if calls := fake.isActiveCallCount(); calls != 3 {
		t.Errorf("inner IsActive calls = %d, want 3 (found result must be cached)", calls)
	}
}

func TestCachingAdapter_ValidationErrorDelegatedNotCached(t *testing.T) {
	t.Parallel()
	fake := newFakeAdapter()
	clk := clock.NewDeterministic(testStart())
	cached := NewCachingAdapter(fake, 10*time.Second, clk)
	ctx := context.Background()

	for i := range 2 {
		if _, err := cached.IsActive(ctx, ""); !errors.Is(err, ErrBillingRefRequired) {
			t.Fatalf("IsActive(\"\") call %d error = %v, want ErrBillingRefRequired", i+1, err)
		}
	}
	if calls := fake.isActiveCallCount(); calls != 2 {
		t.Errorf("inner IsActive calls = %d, want 2 (validation stays inner's job; errors not cached)", calls)
	}
}

func TestCachingAdapter_DefaultTTLAppliedWhenNonPositive(t *testing.T) {
	t.Parallel()
	for name, ttl := range map[string]time.Duration{
		"zero":     0,
		"negative": -time.Second,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeAdapter()
			fake.setActive("ref-default", true)
			clk := clock.NewDeterministic(testStart())
			cached := NewCachingAdapter(fake, ttl, clk)

			mustIsActive(t, cached, "ref-default")
			clk.Advance(DefaultCacheTTL - time.Second)
			mustIsActive(t, cached, "ref-default")
			if calls := fake.isActiveCallCount(); calls != 1 {
				t.Errorf("inner IsActive calls just before 30s = %d, want 1 (default TTL in effect)", calls)
			}
			clk.Advance(time.Second)
			mustIsActive(t, cached, "ref-default")
			if calls := fake.isActiveCallCount(); calls != 2 {
				t.Errorf("inner IsActive calls at 30s = %d, want 2 (default TTL expired)", calls)
			}
		})
	}
}

func TestCachingAdapter_OnRegisterPassesThroughWithoutSeedingCache(t *testing.T) {
	t.Parallel()
	fake := newFakeAdapter()
	clk := clock.NewDeterministic(testStart())
	cached := NewCachingAdapter(fake, 10*time.Second, clk)
	ctx := context.Background()

	req := OnRegisterRequest{BillingRef: "ref-reg", Subdomain: "agent.example.com", Active: true}
	acct, err := cached.OnRegister(ctx, req)
	if err != nil {
		t.Fatalf("OnRegister error = %v, want nil", err)
	}
	if acct.BillingRef != req.BillingRef || acct.Subdomain != req.Subdomain || !acct.Active {
		t.Errorf("OnRegister account = %+v, want passthrough of %+v", acct, req)
	}
	if calls := fake.onRegisterCallCount(); calls != 1 {
		t.Errorf("inner OnRegister calls = %d, want 1", calls)
	}

	// Registration is not a status read: the first IsActive after OnRegister
	// must still hit the inner adapter (nothing was seeded).
	fake.setActive("ref-reg", true)
	mustIsActive(t, cached, "ref-reg")
	if calls := fake.isActiveCallCount(); calls != 1 {
		t.Errorf("inner IsActive calls after OnRegister = %d, want 1 (cache not seeded by register)", calls)
	}
}

// TestCachingAdapter_ReclaimsExpiredEntries checks the cleanup: entries whose
// time has run out are removed from the map when a later write happens, so
// the cache does not keep growing while the process runs. The test looks at
// the entry count directly, because through IsActive alone the cleanup cannot
// be seen — an expired entry and a missing one give the same answer.
func TestCachingAdapter_ReclaimsExpiredEntries(t *testing.T) {
	t.Parallel()
	fake := newFakeAdapter()
	fake.setActive("ref-stale-a", true)
	fake.setActive("ref-stale-b", false)
	fake.setActive("ref-fresh", true)
	clk := clock.NewDeterministic(testStart())
	cached := NewCachingAdapter(fake, 10*time.Second, clk)

	mustIsActive(t, cached, "ref-stale-a")
	mustIsActive(t, cached, "ref-stale-b")
	if got := cacheEntryCount(cached); got != 2 {
		t.Fatalf("entries after two reads = %d, want 2", got)
	}

	// Past both entries' TTL, the next write's sweep must reclaim them and
	// keep only the entry just written.
	clk.Advance(10 * time.Second)
	mustIsActive(t, cached, "ref-fresh")
	if got := cacheEntryCount(cached); got != 1 {
		t.Errorf("entries after sweep = %d, want 1 (both expired entries reclaimed)", got)
	}
}

func cacheEntryCount(c *CachingAdapter) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

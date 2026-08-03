package sor

import (
	"context"
	"sync"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// DefaultCacheTTL is the cache lifetime applied when NewCachingAdapter is
// constructed with a non-positive TTL. Thirty seconds is the documented
// default for the status pull: short enough that an operator's change in the
// SoR converges within one TTL, long enough to keep the SoR off the
// per-transaction hot path.
const DefaultCacheTTL = 30 * time.Second

// cacheEntry is one cached IsActive result. Only successful reads are stored;
// an entry is live until expiresAt (exclusive).
type cacheEntry struct {
	active    bool
	expiresAt time.Time
}

// CachingAdapter is a short-TTL read-through cache over an inner Adapter's
// IsActive. The SoR remains the single source of truth for the active flag;
// this decorator only bounds how often the Exchange pulls it — a stale value
// is served for at most one TTL, then re-read from the inner adapter. One
// rare exception: when two calls see an expired entry at the same time, both
// ask the SoR, and the slower answer is written to the cache last — even if
// it is the older one. An out-of-date value can then live for up to two
// TTLs before the next re-read fixes it. Both
// true and false results are cached; errors (including ErrAccountNotFound)
// never are, so the next call always retries the inner adapter.
//
// Old entries do not stay in memory forever: when the cache stores a new
// value, it also (at most once per TTL) removes every entry whose time has
// run out. So the cache only holds entries used recently, and its size does
// not keep growing while the process runs.
type CachingAdapter struct {
	inner Adapter
	ttl   time.Duration
	clk   clock.Clock

	mu        sync.Mutex
	entries   map[string]cacheEntry // billing_ref → cached IsActive result
	nextSweep time.Time             // earliest time the next expired-entry sweep may run
}

// NewCachingAdapter decorates inner with a read-through IsActive cache whose
// entries live for ttl. A non-positive ttl selects DefaultCacheTTL. Time is
// read exclusively through clk (per ADR-008 D1, time as a port).
func NewCachingAdapter(inner Adapter, ttl time.Duration, clk clock.Clock) *CachingAdapter {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &CachingAdapter{
		inner:   inner,
		ttl:     ttl,
		clk:     clk,
		entries: map[string]cacheEntry{},
	}
}

// OnRegister is a pure passthrough: registration is not a status read, and the
// pull (IsActive) is the only status path, so it neither seeds nor invalidates
// the cache entry for its billing_ref.
func (c *CachingAdapter) OnRegister(ctx context.Context, req OnRegisterRequest) (Account, error) {
	return c.inner.OnRegister(ctx, req)
}

// IsActive returns the cached active flag for billingRef when a live entry
// exists, and otherwise reads through to the inner adapter, caching a
// successful result until now+ttl. Errors are returned as-is and never
// cached. Argument validation (an empty billingRef) is the inner adapter's
// job — the miss path simply delegates, and the resulting error is not
// cached, so this decorator adds no validation of its own.
func (c *CachingAdapter) IsActive(ctx context.Context, billingRef string) (bool, error) {
	now := c.clk.Now()

	c.mu.Lock()
	entry, ok := c.entries[billingRef]
	c.mu.Unlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.active, nil
	}

	active, err := c.inner.IsActive(ctx, billingRef)
	if err != nil {
		return false, err
	}

	c.mu.Lock()
	c.entries[billingRef] = cacheEntry{active: active, expiresAt: now.Add(c.ttl)}
	c.sweepLocked(now)
	c.mu.Unlock()
	return active, nil
}

// sweepLocked removes every entry whose time has run out. It does real work
// at most once per TTL — cleaning on every write would be wasted effort,
// since new entries can only expire after a full TTL anyway. The caller must
// hold c.mu.
func (c *CachingAdapter) sweepLocked(now time.Time) {
	if now.Before(c.nextSweep) {
		return
	}
	for ref, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, ref)
		}
	}
	c.nextSweep = now.Add(c.ttl)
}

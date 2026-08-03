package publisher

import (
	"sync"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// negCache remembers, for a short TTL, subdomains that resolved to nothing, so an
// unauthenticated flood of well-formed unknown hosts does not hit Vault and Postgres
// on every request. It is deliberately capped: the positive cache is bounded by the
// count of real agents, but negatives are attacker-chosen, so this cache evicts to a
// fixed size rather than growing with the traffic it is meant to absorb. A false
// miss only costs one backend round-trip, so an arbitrary eviction is acceptable.
type negCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	limit int
	clock clock.Clock
	m     map[string]time.Time // subdomain -> expiry
}

func newNegCache(ttl time.Duration, limit int, clk clock.Clock) *negCache {
	return &negCache{ttl: ttl, limit: limit, clock: clk, m: make(map[string]time.Time)}
}

// has reports whether subdomain is a live negative entry, dropping it if expired.
func (c *negCache) has(subdomain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[subdomain]
	if !ok {
		return false
	}
	if !c.clock.Now().Before(exp) {
		delete(c.m, subdomain)
		return false
	}
	return true
}

// put records subdomain as absent for the TTL, evicting one entry first if the cache
// is at its limit.
func (c *negCache) put(subdomain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.m[subdomain]; !exists && len(c.m) >= c.limit {
		c.evictOne()
	}
	c.m[subdomain] = c.clock.Now().Add(c.ttl)
}

// delete removes any negative entry for subdomain (e.g. once it becomes real).
func (c *negCache) delete(subdomain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, subdomain)
}

// evictOne drops one entry, preferring an already-expired one, else an arbitrary
// one (Go map iteration order is randomized). Caller holds the lock.
func (c *negCache) evictOne() {
	now := c.clock.Now()
	for k, exp := range c.m {
		if !now.Before(exp) {
			delete(c.m, k)
			return
		}
	}
	for k := range c.m {
		delete(c.m, k)
		return
	}
}

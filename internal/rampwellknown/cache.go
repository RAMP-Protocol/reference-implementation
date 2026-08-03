package rampwellknown

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// Default cache lifetimes. A manifest rotates slowly (keys carry their own
// not_before/not_after), so a multi-minute-to-hour positive TTL is fine; a
// short negative TTL bounds how long a domain's absence is remembered.
const (
	DefaultCacheTTL    = time.Hour
	DefaultNegativeTTL = 5 * time.Minute
)

// CacheOptions configures a Cache.
type CacheOptions struct {
	// Client performs origin GETs. It is REQUIRED: the SSRF-guarded client is
	// SDK-owned, constructed once from resolvers.NewGuardedClientFromEnv at the
	// caller's composition root and injected here. A nil Client fails loud with
	// ErrNoClient at fetch time — this package keeps no in-package guarded default.
	Client HTTPDoer
	// Scheme/Port shape the fetch URL for bare hosts (local/compose stacks).
	Scheme string
	Port   string
	// TTL bounds positive entries (default 1h); honored Cache-Control max-age
	// shortens but never extends it. NegativeTTL bounds 404 memory (default 5m).
	// Timeout bounds a single fetch (default 5s).
	TTL         time.Duration
	NegativeTTL time.Duration
	Timeout     time.Duration
	// Clk is the time source for TTL comparisons; default clock.System{}.
	Clk clock.Clock
	// ExpectRole, when set, makes every fetched manifest's role be asserted.
	ExpectRole Role
}

// Cache fetches and caches manifests by host with single-flighted origin calls,
// a positive TTL (honoring Cache-Control max-age, capped at TTL), and a negative
// TTL for absent (404) domains. It is the shared publisher-manifest cache for
// the Exchange contributor-authz check and the Broker routing probe.
//
// The positive (host→manifest) core lives in the shared docStore; Cache
// adds the negative (404) map and Cache-Control handling on top.
type Cache struct {
	store       *docStore[*Manifest]
	client      HTTPDoer
	scheme      string
	port        string
	ttl         time.Duration
	negativeTTL time.Duration
	timeout     time.Duration
	clk         clock.Clock
	expectRole  Role

	negMu    sync.Mutex
	negative map[string]time.Time
}

// NewCache constructs a Cache with defaults applied.
func NewCache(opts CacheOptions) *Cache {
	if opts.Scheme == "" {
		opts.Scheme = "https"
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultCacheTTL
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = DefaultNegativeTTL
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Clk == nil {
		opts.Clk = clock.System{}
	}
	return &Cache{
		store:       newDocStore[*Manifest](opts.Clk),
		client:      opts.Client,
		scheme:      opts.Scheme,
		port:        opts.Port,
		ttl:         opts.TTL,
		negativeTTL: opts.NegativeTTL,
		timeout:     opts.Timeout,
		clk:         opts.Clk,
		expectRole:  opts.ExpectRole,
		negative:    map[string]time.Time{},
	}
}

// Get returns host's cached manifest, fetching through single-flight on a miss.
// A domain that serves no manifest yields (nil, ErrNoManifest).
func (c *Cache) Get(ctx context.Context, host string) (*Manifest, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	if m, ok := c.store.get(host); ok {
		return m, nil
	}
	if c.readNegative(host) {
		return nil, ErrNoManifest
	}
	return c.single(ctx, host)
}

// Refresh forces a fresh origin fetch, bypassing (and replacing) any cache entry.
func (c *Cache) Refresh(ctx context.Context, host string) (*Manifest, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	c.store.drop(host)
	c.clearNegative(host)
	return c.single(ctx, host)
}

func (c *Cache) single(ctx context.Context, host string) (*Manifest, error) {
	return c.store.single(host, func() (*Manifest, error) {
		if c.readNegative(host) {
			return nil, ErrNoManifest
		}
		return c.load(ctx, host)
	})
}

// load performs the origin GET, schema-validates + decodes the body, and stores
// the result (negative on 404, positive otherwise with the header-derived TTL).
func (c *Cache) load(ctx context.Context, host string) (*Manifest, error) {
	if c.client == nil {
		return nil, ErrNoClient
	}
	rawURL, err := ManifestURL(host, c.scheme, c.port)
	if err != nil {
		return nil, err
	}
	status, header, body, err := httpGet(ctx, c.client, rawURL, c.timeout)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		c.storeNegative(host)
		return nil, ErrNoManifest
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("%w: %s: status %d", ErrFetch, rawURL, status)
	}
	m, err := ParseManifest(body, c.expectRole)
	if err != nil {
		return nil, err
	}
	c.storePositive(host, m, c.ttlFrom(header))
	return m, nil
}

// storePositive caches a fetched manifest and clears any negative entry for host.
func (c *Cache) storePositive(host string, m *Manifest, ttl time.Duration) {
	c.store.put(host, m, ttl)
	c.clearNegative(host)
}

// storeNegative records a 404 for host and drops any positive entry.
func (c *Cache) storeNegative(host string) {
	c.negMu.Lock()
	c.negative[host] = c.clk.Now().Add(c.negativeTTL)
	c.negMu.Unlock()
	c.store.drop(host)
}

func (c *Cache) readNegative(host string) bool {
	c.negMu.Lock()
	defer c.negMu.Unlock()
	until, ok := c.negative[host]
	return ok && c.clk.Now().Before(until)
}

func (c *Cache) clearNegative(host string) {
	c.negMu.Lock()
	delete(c.negative, host)
	c.negMu.Unlock()
}

// ttlFrom honors a Cache-Control: max-age shorter than the configured TTL; an
// origin asking for a longer lifetime is ignored to bound staleness.
func (c *Cache) ttlFrom(header http.Header) time.Duration {
	for _, part := range strings.Split(header.Get("Cache-Control"), ",") {
		const prefix = "max-age="
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, prefix) {
			continue
		}
		secs, err := strconv.Atoi(strings.TrimPrefix(part, prefix))
		if err == nil && secs >= 0 {
			if d := time.Duration(secs) * time.Second; d < c.ttl {
				return d
			}
		}
	}
	return c.ttl
}

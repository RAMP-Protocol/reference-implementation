// Package probe discovers provider ramp.json manifests and caches them.
//
// It fetches /.well-known/ramp.json over HTTP for a given domain. Responses
// are cached for TTL in Redis (when available) or in-process otherwise.
// Callers use Probe to translate a candidate domain into a Manifest (from
// which an Exchange endpoint is extracted) OR a well-defined "not found"
// indication (which triggers the bare-URL fallback in the resolver).
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultTTL is applied when the caller does not configure one.
const DefaultTTL = time.Hour

// AuthorizedExchange mirrors the proto AuthorizedExchange message. One entry
// per Exchange that represents the publisher at this domain.
type AuthorizedExchange struct {
	Domain            string   `json:"domain"`
	Endpoint          string   `json:"endpoint"`
	SupportedProfiles []string `json:"supported_profiles,omitempty"`
}

// Manifest is the subset of /.well-known/ramp.json the Broker needs.
type Manifest struct {
	Ver       string               `json:"ver"`
	Provider  string               `json:"provider"`
	Exchanges []AuthorizedExchange `json:"exchanges"`
}

// Result distinguishes the three probe outcomes for downstream branching.
type Result struct {
	// Present is true when a manifest was fetched successfully.
	Present bool
	// Manifest is populated when Present is true.
	Manifest Manifest
	// FetchedAt is populated when Present is true.
	FetchedAt time.Time
}

// ErrInvalidDomain is returned for empty or obviously invalid input.
var ErrInvalidDomain = errors.New("probe: invalid domain")

// HTTPDoer is the minimal interface the Prober needs from an *http.Client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Options tunes the Prober.
type Options struct {
	TTL     time.Duration
	Timeout time.Duration
	Scheme  string // "https" by default; tests may override.
}

// Prober fetches and caches ramp.json manifests.
type Prober struct {
	client HTTPDoer
	redis  *redis.Client
	mem    *memCache
	logger *slog.Logger
	opts   Options
}

// New constructs a Prober. redisClient may be nil — in that case, an
// in-process TTL cache is used instead.
func New(client HTTPDoer, redisClient *redis.Client, logger *slog.Logger, opts Options) *Prober {
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Scheme == "" {
		opts.Scheme = "https"
	}
	return &Prober{
		client: client,
		redis:  redisClient,
		mem:    newMemCache(),
		logger: logger,
		opts:   opts,
	}
}

// Probe returns the manifest for a domain, fetching or hitting cache as needed.
// Result.Present == false indicates the bare-URL fallback should be used.
func (p *Prober) Probe(ctx context.Context, domain string) (Result, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return Result{}, ErrInvalidDomain
	}
	if cached, ok := p.readCache(ctx, domain); ok {
		return cached, nil
	}
	res, err := p.fetch(ctx, domain)
	if err != nil {
		return Result{}, err
	}
	p.writeCache(ctx, domain, res)
	return res, nil
}

func (p *Prober) fetch(ctx context.Context, domain string) (Result, error) {
	url := fmt.Sprintf("%s://%s/.well-known/ramp.json", p.opts.Scheme, domain)
	reqCtx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, fmt.Errorf("probe: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.InfoContext(ctx, "ramp.json fetch failed", "domain", domain, "err", err)
		return Result{Present: false, FetchedAt: time.Now().UTC()}, nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return Result{Present: false, FetchedAt: time.Now().UTC()}, nil
	}
	if resp.StatusCode >= 400 {
		p.logger.InfoContext(ctx, "ramp.json non-200",
			"domain", domain, "status", resp.StatusCode)
		return Result{Present: false, FetchedAt: time.Now().UTC()}, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return Result{}, fmt.Errorf("probe: read body: %w", err)
	}
	var manifest Manifest
	if decodeErr := json.Unmarshal(body, &manifest); decodeErr != nil {
		p.logger.InfoContext(ctx, "ramp.json decode failed",
			"domain", domain, "err", decodeErr)
		return Result{Present: false, FetchedAt: time.Now().UTC()}, nil
	}
	return Result{Present: true, Manifest: manifest, FetchedAt: time.Now().UTC()}, nil
}

func (p *Prober) readCache(ctx context.Context, domain string) (Result, bool) {
	if p.redis != nil {
		raw, err := p.redis.Get(ctx, cacheKey(domain)).Bytes()
		if err == nil {
			var r Result
			if unmarshalErr := json.Unmarshal(raw, &r); unmarshalErr == nil {
				return r, true
			}
		}
		return Result{}, false
	}
	return p.mem.get(domain)
}

func (p *Prober) writeCache(ctx context.Context, domain string, r Result) {
	if p.redis != nil {
		raw, err := json.Marshal(r)
		if err == nil {
			_ = p.redis.Set(ctx, cacheKey(domain), raw, p.opts.TTL).Err()
		}
		return
	}
	p.mem.set(domain, r, time.Now().Add(p.opts.TTL))
}

func cacheKey(domain string) string {
	return "probe:rampjson:" + domain
}

// -----------------------------------------------------------------------------
// In-process TTL cache (used when Redis is not configured).

type memCache struct {
	mu    sync.RWMutex
	items map[string]memEntry
}

type memEntry struct {
	res      Result
	expireAt time.Time
}

func newMemCache() *memCache {
	return &memCache{items: make(map[string]memEntry)}
}

func (c *memCache) get(domain string) (Result, bool) {
	c.mu.RLock()
	entry, ok := c.items[domain]
	c.mu.RUnlock()
	if !ok {
		return Result{}, false
	}
	if time.Now().After(entry.expireAt) {
		c.mu.Lock()
		delete(c.items, domain)
		c.mu.Unlock()
		return Result{}, false
	}
	return entry.res, true
}

func (c *memCache) set(domain string, r Result, expireAt time.Time) {
	c.mu.Lock()
	c.items[domain] = memEntry{res: r, expireAt: expireAt}
	c.mu.Unlock()
}

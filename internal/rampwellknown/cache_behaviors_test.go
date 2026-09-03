package rampwellknown_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// These cases port the cache-behavior guards that moved from the deleted
// internal/manifestcache suite onto rampwellknown.Cache. The proto Manifest
// carries no expiry field, so TTL/negative-cache behavior is asserted through
// observable re-fetches (testutil.Origin.Hits) plus a deterministic clock,
// rather than by inspecting internal expiry timestamps.

func newPublisherCacheTTL(clk clock.Clock, ttl time.Duration) *rampwellknown.Cache {
	return rampwellknown.NewCache(rampwellknown.CacheOptions{
		Client:     testutil.Client(),
		Clk:        clk,
		ExpectRole: rampwellknown.RolePublisher,
		TTL:        ttl,
	})
}

func TestCache_NegativeCacheStickyThenExpires(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(nil)
	origin.SetManifestStatus(http.StatusNotFound)
	defer origin.Close()
	clk := clock.NewDeterministic(anchor)
	c := newPublisherCache(clk)
	ctx := context.Background()

	if _, err := c.Get(ctx, origin.URL); !errors.Is(err, rampwellknown.ErrNoDocument) {
		t.Fatalf("first Get = %v, want ErrNoDocument", err)
	}
	// Within the negative TTL (default 5m) the absence is cached: no re-probe.
	clk.Advance(4 * time.Minute)
	if _, err := c.Get(ctx, origin.URL); !errors.Is(err, rampwellknown.ErrNoDocument) {
		t.Fatalf("cached negative = %v, want ErrNoDocument", err)
	}
	if got := origin.Hits(); got != 1 {
		t.Fatalf("origin hits = %d, want 1 (negative cached)", got)
	}
	// Past the negative TTL the entry expires and the origin is re-probed.
	clk.Advance(2 * time.Minute) // 6m total
	if _, err := c.Get(ctx, origin.URL); !errors.Is(err, rampwellknown.ErrNoDocument) {
		t.Fatalf("post-expiry Get = %v, want ErrNoDocument", err)
	}
	if got := origin.Hits(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 after negative expiry", got)
	}
}

func TestCache_MalformedBodyNotCached(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin([]byte("not-json"))
	defer origin.Close()
	c := newPublisherCache(clock.NewDeterministic(anchor))
	ctx := context.Background()

	_, err := c.Get(ctx, origin.URL)
	if !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
		t.Fatalf("malformed Get = %v, want ErrSchemaInvalid", err)
	}
	// A malformed response must not be cached — the next Get re-fetches.
	if _, err := c.Get(ctx, origin.URL); !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
		t.Fatalf("second malformed Get = %v, want ErrSchemaInvalid", err)
	}
	if got := origin.Hits(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (malformed not cached)", got)
	}
}

func TestCache_Non2xxNotCached(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(nil)
	origin.SetManifestStatus(http.StatusInternalServerError)
	defer origin.Close()
	c := newPublisherCache(clock.NewDeterministic(anchor))
	ctx := context.Background()

	_, err := c.Get(ctx, origin.URL)
	if !errors.Is(err, rampwellknown.ErrFetch) || errors.Is(err, rampwellknown.ErrNoDocument) {
		t.Fatalf("500 Get = %v, want ErrFetch (not ErrNoDocument)", err)
	}
	if _, err := c.Get(ctx, origin.URL); !errors.Is(err, rampwellknown.ErrFetch) {
		t.Fatalf("second 500 Get = %v, want ErrFetch", err)
	}
	if got := origin.Hits(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (5xx not cached)", got)
	}
}

func TestCache_SingleFlightCollapsesConcurrentGets(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(publisherManifestJSON())
	defer origin.Close()
	release := origin.Block()
	c := newPublisherCache(clock.NewDeterministic(anchor))

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for range n {
		go func() {
			defer wg.Done()
			_, err := c.Get(context.Background(), origin.URL)
			errs <- err
		}()
	}
	// Let every caller converge on the single-flight slot before releasing.
	time.Sleep(50 * time.Millisecond)
	release()
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Get: %v", err)
		}
	}
	if got := origin.Hits(); got != 1 {
		t.Fatalf("origin hits = %d, want 1 under single-flight", got)
	}
}

func TestCache_MaxAgeShortensTTL(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(publisherManifestJSON())
	origin.SetCacheControl("max-age=30, public")
	defer origin.Close()
	clk := clock.NewDeterministic(anchor)
	c := newPublisherCache(clk) // default TTL 1h, shortened to 30s by max-age
	ctx := context.Background()

	if _, err := c.Get(ctx, origin.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
	clk.Advance(20 * time.Second)
	if _, err := c.Get(ctx, origin.URL); err != nil {
		t.Fatalf("Get within max-age: %v", err)
	}
	if got := origin.Hits(); got != 1 {
		t.Fatalf("origin hits = %d, want 1 within max-age", got)
	}
	clk.Advance(11 * time.Second) // 31s total > 30s max-age
	if _, err := c.Get(ctx, origin.URL); err != nil {
		t.Fatalf("Get after max-age: %v", err)
	}
	if got := origin.Hits(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 after max-age expiry", got)
	}
}

func TestCache_MaxAgeLongerThanTTLIgnored(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(publisherManifestJSON())
	origin.SetCacheControl("max-age=86400") // a day — must not extend past TTL
	defer origin.Close()
	clk := clock.NewDeterministic(anchor)
	c := newPublisherCacheTTL(clk, 5*time.Minute)
	ctx := context.Background()

	if _, err := c.Get(ctx, origin.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
	clk.Advance(4 * time.Minute)
	if _, err := c.Get(ctx, origin.URL); err != nil {
		t.Fatalf("Get within TTL: %v", err)
	}
	if got := origin.Hits(); got != 1 {
		t.Fatalf("origin hits = %d, want 1 within configured TTL", got)
	}
	clk.Advance(2 * time.Minute) // 6m total > 5m TTL (day-long max-age ignored)
	if _, err := c.Get(ctx, origin.URL); err != nil {
		t.Fatalf("Get after TTL: %v", err)
	}
	if got := origin.Hits(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (longer max-age ignored)", got)
	}
}

func TestCache_RefreshBypassesCache(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(publisherManifestJSON())
	defer origin.Close()
	c := newPublisherCache(clock.NewDeterministic(anchor))
	ctx := context.Background()

	if _, err := c.Get(ctx, origin.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := c.Refresh(ctx, origin.URL); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := origin.Hits(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 after Refresh", got)
	}
}

func TestCache_EmptyHostRejected(t *testing.T) {
	t.Parallel()
	c := newPublisherCache(clock.NewDeterministic(anchor))
	if _, err := c.Get(context.Background(), "   "); !errors.Is(err, rampwellknown.ErrInvalidHost) {
		t.Fatalf("empty-host Get = %v, want ErrInvalidHost", err)
	}
}

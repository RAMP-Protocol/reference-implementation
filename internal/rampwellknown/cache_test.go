package rampwellknown_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

func publisherManifestJSON() []byte {
	m := testutil.Manifest(rampwellknown.RolePublisher, "pub.example")
	m.Exchanges = []*rampv1.AuthorizedExchange{
		testutil.PublisherExchange("x.example", "https://x.example/ramp",
			rampv1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT),
	}
	m.CatalogContributors = []*rampv1.CatalogContributor{
		{Domain: "verifier.example", Relationship: "verifier"},
	}
	return testutil.MarshalManifest(m)
}

func newPublisherCache(clk clock.Clock) *rampwellknown.Cache {
	return rampwellknown.NewCache(rampwellknown.CacheOptions{
		Client:     http.DefaultClient,
		Clk:        clk,
		ExpectRole: rampwellknown.RolePublisher,
	})
}

func TestCache_GetAndAuthorizes(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(publisherManifestJSON())
	defer origin.Close()
	c := newPublisherCache(clock.NewDeterministic(anchor))

	m, err := c.Get(context.Background(), origin.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !rampwellknown.AuthorizesContributor(m, "pub.example") {
		t.Error("publisher domain should authorize itself")
	}
	if !rampwellknown.AuthorizesContributor(m, "verifier.example") {
		t.Error("listed contributor should be authorized")
	}
	if rampwellknown.AuthorizesContributor(m, "stranger.example") {
		t.Error("unlisted caller must not be authorized")
	}
}

func TestCache_RoleAssert(t *testing.T) {
	t.Parallel()
	// The negative-cache path (404 → ErrNoManifest), including stickiness and
	// expiry, is covered by cache_behaviors_test.go's
	// TestCache_NegativeCacheStickyThenExpires.
	_, key := testutil.NewSigningKey("k", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	origin := testutil.NewOrigin(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleAgent, "a.example", key),
	))
	defer origin.Close()
	c := newPublisherCache(clock.NewDeterministic(anchor))
	if _, err := c.Get(context.Background(), origin.URL); !errors.Is(err, rampwellknown.ErrRoleMismatch) {
		t.Fatalf("want ErrRoleMismatch, got %v", err)
	}
}

func TestCache_TTLServesFromCache(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(publisherManifestJSON())
	defer origin.Close()
	clk := clock.NewDeterministic(anchor)
	c := newPublisherCache(clk)

	if _, err := c.Get(context.Background(), origin.URL); err != nil {
		t.Fatalf("first get: %v", err)
	}
	origin.SetManifestStatus(http.StatusInternalServerError)
	if _, err := c.Get(context.Background(), origin.URL); err != nil {
		t.Fatalf("cached get should not hit failing origin: %v", err)
	}
	clk.Advance(2 * time.Hour)
	if _, err := c.Get(context.Background(), origin.URL); !errors.Is(err, rampwellknown.ErrFetch) {
		t.Fatalf("want ErrFetch after TTL expiry, got %v", err)
	}
}

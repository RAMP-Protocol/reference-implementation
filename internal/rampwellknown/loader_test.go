package rampwellknown_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

func newLoaderFor(clk clock.Clock) *rampwellknown.Loader {
	return rampwellknown.NewLoader(rampwellknown.LoaderOptions{
		Fetch:       rampwellknown.FetchOptions{Client: testutil.Client()},
		Clk:         clk,
		ManifestTTL: time.Hour,
	})
}

func TestLoaderLookupKey_Active(t *testing.T) {
	t.Parallel()
	priv, key := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	origin := testutil.NewOrigin(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleBroker, "b.example", key),
	))
	defer origin.Close()

	l := newLoaderFor(clock.NewDeterministic(anchor))
	got, err := l.LookupKey(context.Background(), origin.URL, "k1")
	if err != nil {
		t.Fatalf("LookupKey: %v", err)
	}
	if !got.Equal(priv.Public()) {
		t.Fatal("resolved key mismatch")
	}
}

func TestLoaderLookupKey_Sentinels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		kid     string
		from    time.Duration
		until   time.Duration
		lookup  string
		wantErr error
	}{
		{"expired window", "k1", -2 * time.Hour, -time.Hour, "k1", rampwellknown.ErrKeyExpired},
		{"unknown kid", "k1", -time.Hour, time.Hour, "absent", rampwellknown.ErrKeyUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, key := testutil.NewSigningKey(tc.kid, anchor.Add(tc.from), anchor.Add(tc.until))
			origin := testutil.NewOrigin(testutil.MarshalManifest(
				testutil.Manifest(rampwellknown.RoleExchange, "x.example", key),
			))
			defer origin.Close()
			l := newLoaderFor(clock.NewDeterministic(anchor))
			_, err := l.LookupKey(context.Background(), origin.URL, tc.lookup)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestLoaderLookupKey_RotationSelfHeal(t *testing.T) {
	t.Parallel()
	_, k1 := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	origin := testutil.NewOrigin(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleBroker, "b.example", k1),
	))
	defer origin.Close()
	l := newLoaderFor(clock.NewDeterministic(anchor))

	// Prime the cache with the k1-only manifest.
	if _, err := l.LookupKey(context.Background(), origin.URL, "k1"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// Rotate in k2; cache still holds k1-only, so the lookup must self-heal.
	_, k2 := testutil.NewSigningKey("k2", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	origin.SetManifest(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleBroker, "b.example", k1, k2),
	))
	if _, err := l.LookupKey(context.Background(), origin.URL, "k2"); err != nil {
		t.Fatalf("self-heal lookup of rotated-in k2: %v", err)
	}
}

func TestLoaderLookupKey_Revoked(t *testing.T) {
	t.Parallel()
	_, key := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	origin := testutil.NewOrigin(nil)
	defer origin.Close()
	m := testutil.Manifest(rampwellknown.RoleBroker, "b.example", key)
	m.InvalidationUrl = testutil.Ptr(origin.InvalidationURL())
	origin.SetManifest(testutil.MarshalManifest(m))
	origin.SetInvalidation(testutil.MarshalInvalidation(anchor, "k1"))

	l := newLoaderFor(clock.NewDeterministic(anchor))
	_, err := l.LookupKey(context.Background(), origin.URL, "k1")
	if !errors.Is(err, rampwellknown.ErrKeyRevoked) {
		t.Fatalf("want ErrKeyRevoked, got %v", err)
	}
}

func TestLoaderLookupKey_RevocationRollbackIgnored(t *testing.T) {
	t.Parallel()
	_, key := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(1000*time.Hour))
	origin := testutil.NewOrigin(nil)
	defer origin.Close()
	m := testutil.Manifest(rampwellknown.RoleBroker, "b.example", key)
	m.InvalidationUrl = testutil.Ptr(origin.InvalidationURL())
	origin.SetManifest(testutil.MarshalManifest(m))
	// Newer snapshot (as_of == anchor) revokes k1.
	origin.SetInvalidation(testutil.MarshalInvalidation(anchor, "k1"))

	clk := clock.NewDeterministic(anchor)
	l := newLoaderFor(clk)
	if _, err := l.LookupKey(context.Background(), origin.URL, "k1"); !errors.Is(err, rampwellknown.ErrKeyRevoked) {
		t.Fatalf("precondition: want ErrKeyRevoked, got %v", err)
	}
	// A successful fetch of an OLDER (regressed/rolled-back) list must not clear
	// the revocation the loader already learned from the newer snapshot.
	origin.SetInvalidation(testutil.MarshalInvalidation(anchor.Add(-time.Hour)))
	clk.Advance(2 * time.Hour) // expire ManifestTTL → re-fetch + revocation refresh
	if _, err := l.LookupKey(context.Background(), origin.URL, "k1"); !errors.Is(err, rampwellknown.ErrKeyRevoked) {
		t.Fatalf("rollback list (older as_of) must not un-revoke k1; got %v", err)
	}
}

func TestLoaderLookupKey_RevocationForwardProgressApplied(t *testing.T) {
	t.Parallel()
	priv, key := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(1000*time.Hour))
	origin := testutil.NewOrigin(nil)
	defer origin.Close()
	m := testutil.Manifest(rampwellknown.RoleBroker, "b.example", key)
	m.InvalidationUrl = testutil.Ptr(origin.InvalidationURL())
	origin.SetManifest(testutil.MarshalManifest(m))
	origin.SetInvalidation(testutil.MarshalInvalidation(anchor, "k1"))

	clk := clock.NewDeterministic(anchor)
	l := newLoaderFor(clk)
	if _, err := l.LookupKey(context.Background(), origin.URL, "k1"); !errors.Is(err, rampwellknown.ErrKeyRevoked) {
		t.Fatalf("precondition: want ErrKeyRevoked, got %v", err)
	}
	// A strictly-newer snapshot that drops k1 legitimately un-revokes it — the
	// guard gates on as_of ordering, not on content.
	origin.SetInvalidation(testutil.MarshalInvalidation(anchor.Add(time.Hour)))
	clk.Advance(2 * time.Hour)
	got, err := l.LookupKey(context.Background(), origin.URL, "k1")
	if err != nil {
		t.Fatalf("newer empty snapshot should un-revoke k1; got %v", err)
	}
	if !got.Equal(priv.Public()) {
		t.Fatal("resolved key mismatch after un-revocation")
	}
}

func TestLoaderLookupKey_RemovalIsNotRevocation(t *testing.T) {
	t.Parallel()
	// Invariant: a kid dropped from the manifest resolves to ErrKeyUnknown
	// (→ composite falls through to the static bootstrap), never ErrKeyRevoked.
	_, k1 := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(1000*time.Hour))
	origin := testutil.NewOrigin(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleBroker, "b.example", k1),
	))
	defer origin.Close()
	clk := clock.NewDeterministic(anchor)
	l := newLoaderFor(clk)
	if _, err := l.LookupKey(context.Background(), origin.URL, "k1"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// k1 removed; the manifest now carries only k2.
	_, k2 := testutil.NewSigningKey("k2", anchor.Add(-time.Hour), anchor.Add(1000*time.Hour))
	origin.SetManifest(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleBroker, "b.example", k2),
	))
	clk.Advance(2 * time.Hour) // expire TTL → re-fetch the k1-less manifest
	_, err := l.LookupKey(context.Background(), origin.URL, "k1")
	if !errors.Is(err, rampwellknown.ErrKeyUnknown) {
		t.Fatalf("removed kid must be ErrKeyUnknown, got %v", err)
	}
	if errors.Is(err, rampwellknown.ErrKeyRevoked) {
		t.Fatal("removal must not be reported as revocation")
	}
}

func TestLoaderRun_PollerAppliesRevocation(t *testing.T) {
	t.Parallel()
	// The 300s poller is the only thing bounding emergency-revocation latency for
	// a kid revoked AFTER the manifest is cached. Prove a running poller picks up
	// a newly-published revocation without a manifest re-fetch.
	_, key := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(1000*time.Hour))
	origin := testutil.NewOrigin(nil)
	defer origin.Close()
	m := testutil.Manifest(rampwellknown.RoleBroker, "b.example", key)
	m.InvalidationUrl = testutil.Ptr(origin.InvalidationURL())
	origin.SetManifest(testutil.MarshalManifest(m))
	origin.SetInvalidation(testutil.MarshalInvalidation(anchor.Add(-time.Hour))) // nothing revoked yet

	clk := clock.NewDeterministic(anchor)
	l := rampwellknown.NewLoader(rampwellknown.LoaderOptions{
		Fetch:        rampwellknown.FetchOptions{Client: testutil.Client()},
		Clk:          clk,
		ManifestTTL:  100 * time.Hour, // never expires during the test → isolate the poller
		PollInterval: 10 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx)

	// Prime the manifest + an empty revocation snapshot.
	if _, err := l.LookupKey(ctx, origin.URL, "k1"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// Publish a newer snapshot revoking k1.
	origin.SetInvalidation(testutil.MarshalInvalidation(anchor, "k1"))

	// Drive poll ticks by advancing past the (jittered ±10%) interval. Advancing
	// each iteration is robust to the goroutine's first-After registration race.
	deadline := time.Now().Add(5 * time.Second)
	for {
		clk.Advance(12 * time.Second)
		time.Sleep(20 * time.Millisecond) // let the poller goroutine apply the refresh
		if _, err := l.LookupKey(ctx, origin.URL, "k1"); errors.Is(err, rampwellknown.ErrKeyRevoked) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("running poller did not pick up the revocation within the deadline")
		}
	}
}

func TestLoaderLookupKey_TTLServesFromCache(t *testing.T) {
	t.Parallel()
	_, key := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(10*time.Hour))
	origin := testutil.NewOrigin(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleBroker, "b.example", key),
	))
	defer origin.Close()
	clk := clock.NewDeterministic(anchor)
	l := newLoaderFor(clk)

	if _, err := l.LookupKey(context.Background(), origin.URL, "k1"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	// Origin now fails; a cache hit must still succeed within TTL.
	origin.SetManifestStatus(http.StatusInternalServerError)
	if _, err := l.LookupKey(context.Background(), origin.URL, "k1"); err != nil {
		t.Fatalf("cached lookup should not hit origin: %v", err)
	}
	// Past the TTL the cache is cold and the failing origin surfaces.
	clk.Advance(2 * time.Hour)
	if _, err := l.LookupKey(context.Background(), origin.URL, "k1"); !errors.Is(err, rampwellknown.ErrFetch) {
		t.Fatalf("want ErrFetch after TTL expiry, got %v", err)
	}
}

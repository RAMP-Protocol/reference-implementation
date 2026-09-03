package publisher_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
)

// These are pure unit tests over the orchestration/cache/TTL logic: the backends
// are in-memory stubs, so they run under make test-fast with no container.

const validSub = "agent-1.rampmcp.org"

var anchor = time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

type stubKeys struct {
	keys  []keystore.Key
	err   error
	calls int
}

func (s *stubKeys) List(_ context.Context, _ string) ([]keystore.Key, error) {
	s.calls++
	return s.keys, s.err
}

type stubCards struct {
	card directory.Card
	err  error
}

func (s *stubCards) BySubdomain(_ context.Context, _ string) (directory.Card, error) {
	return s.card, s.err
}

type stubRevocations struct {
	asOf    int64
	revoked []string
	err     error
}

func (s *stubRevocations) BySubdomain(_ context.Context, _ string) (int64, []string, error) {
	return s.asOf, s.revoked, s.err
}

// blockingKeys blocks its FIRST List call until released, recording the context it
// received; later calls return immediately. It lets a test interleave an in-flight
// build with a caller cancellation or an Invalidate.
type blockingKeys struct {
	keys    []keystore.Key
	mu      sync.Mutex
	calls   int
	gotCtx  context.Context //nolint:containedctx // captured only to assert cancellation was detached
	started chan struct{}
	release chan struct{}
}

func newBlockingKeys(keys []keystore.Key) *blockingKeys {
	return &blockingKeys{keys: keys, started: make(chan struct{}), release: make(chan struct{})}
}

func (b *blockingKeys) List(ctx context.Context, _ string) ([]keystore.Key, error) {
	b.mu.Lock()
	b.calls++
	first := b.calls == 1
	if first {
		b.gotCtx = ctx
	}
	b.mu.Unlock()
	if first {
		close(b.started)
		<-b.release
	}
	return b.keys, nil
}

func (b *blockingKeys) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// ctxWaitKeys blocks until its context is cancelled, then returns the context error —
// a backend that never answers, used to exercise the build timeout.
type ctxWaitKeys struct{}

func (ctxWaitKeys) List(ctx context.Context, _ string) ([]keystore.Key, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func aKey(t *testing.T) keystore.Key {
	t.Helper()
	return keyWithWindow(t, anchor, anchor.AddDate(1, 0, 0))
}

func keyWithWindow(t *testing.T, notBefore, notAfter time.Time) keystore.Key {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return keystore.Key{Public: pub, Window: keystore.Window{NotBefore: notBefore, NotAfter: notAfter}}
}

func keyCount(t *testing.T, body []byte) int {
	t.Helper()
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse directory: %v", err)
	}
	return len(doc.Keys)
}

func newSvc(t *testing.T, cfg publisher.Config) *publisher.Service {
	t.Helper()
	if cfg.Clock == nil {
		cfg.Clock = clock.NewDeterministic(anchor)
	}
	if cfg.Revocations == nil {
		cfg.Revocations = &stubRevocations{}
	}
	// Default to an UNREGISTERED subdomain so a test that says nothing about the
	// account row gets no overlay, and every existing presence expectation is
	// unchanged by the overlay's arrival.
	if cfg.Registrations == nil {
		cfg.Registrations = &stubRegistrations{err: account.ErrNotFound}
	}
	svc, err := publisher.New(cfg)
	if err != nil {
		t.Fatalf("publisher.New: %v", err)
	}
	return svc
}

func TestDirectoryPresent_CardAbsent(t *testing.T) {
	t.Parallel()
	svc := newSvc(t, publisher.Config{
		Keys:  &stubKeys{keys: []keystore.Key{aKey(t)}},
		Cards: &stubCards{err: directory.ErrCardNotFound},
	})
	if body, err := svc.Directory(context.Background(), validSub); err != nil || len(body) == 0 {
		t.Fatalf("Directory = (%d bytes, %v), want non-empty, nil", len(body), err)
	}
	if _, err := svc.Card(context.Background(), validSub); !errors.Is(err, publisher.ErrAbsent) {
		t.Fatalf("Card err = %v, want ErrAbsent", err)
	}
}

func TestCardPresent_DirectoryAbsent(t *testing.T) {
	t.Parallel()
	svc := newSvc(t, publisher.Config{
		Keys:  &stubKeys{}, // no keys
		Cards: &stubCards{card: directory.Card{ClientName: "x", ClientURI: "https://x"}},
	})
	if _, err := svc.Directory(context.Background(), validSub); !errors.Is(err, publisher.ErrAbsent) {
		t.Fatalf("Directory err = %v, want ErrAbsent (no keys)", err)
	}
	if body, err := svc.Card(context.Background(), validSub); err != nil || len(body) == 0 {
		t.Fatalf("Card = (%d bytes, %v), want non-empty, nil", len(body), err)
	}
}

// The revocation_url a directory advertises must be the agent's OWN host, derived
// per subdomain — not one shared value. A WBA consumer host-anchors the advertised
// URL and skips a cross-host one, so a single static URL would leave every agent but
// one with an unpolled (silently fail-open) revocation list. Driving two subdomains
// through one service proves the URL tracks the subdomain, not the process config.
func TestDirectoryAdvertisesPerSubdomainRevocationURL(t *testing.T) {
	t.Parallel()
	svc := newSvc(t, publisher.Config{
		Keys:  &stubKeys{keys: []keystore.Key{aKey(t)}},
		Cards: &stubCards{err: directory.ErrCardNotFound},
	})
	for _, sub := range []string{"agent-1.rampmcp.org", "agent-2.rampmcp.org"} {
		body, err := svc.Directory(context.Background(), sub)
		if err != nil {
			t.Fatalf("%s: Directory: %v", sub, err)
		}
		var doc struct {
			RevocationURL string `json:"revocation_url"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("%s: parse directory: %v", sub, err)
		}
		want := "https://" + sub + rampwellknown.RevocationPath
		if doc.RevocationURL != want {
			t.Fatalf("%s: revocation_url = %q, want %q", sub, doc.RevocationURL, want)
		}
	}
}

func TestDirectoryAbsentWhenNoKeys(t *testing.T) {
	t.Parallel()
	svc := newSvc(t, publisher.Config{Keys: &stubKeys{}, Cards: &stubCards{err: directory.ErrCardNotFound}})
	if _, err := svc.Directory(context.Background(), validSub); !errors.Is(err, publisher.ErrAbsent) {
		t.Fatalf("Directory err = %v, want ErrAbsent", err)
	}
}

func TestMalformedSubdomainSkipsBackend(t *testing.T) {
	t.Parallel()
	keys := &stubKeys{keys: []keystore.Key{aKey(t)}}
	svc := newSvc(t, publisher.Config{Keys: keys, Cards: &stubCards{err: directory.ErrCardNotFound}})
	if _, err := svc.Directory(context.Background(), "bad_label.rampmcp.org"); !errors.Is(err, publisher.ErrAbsent) {
		t.Fatalf("Directory err = %v, want ErrAbsent", err)
	}
	if keys.calls != 0 {
		t.Fatalf("KeyStore.List called %d times for a malformed host, want 0", keys.calls)
	}
}

func TestBackendUnavailableMapsToErrUnavailable(t *testing.T) {
	t.Parallel()
	svc := newSvc(t, publisher.Config{Keys: &stubKeys{err: keystore.ErrUnavailable}, Cards: &stubCards{err: directory.ErrCardNotFound}})
	if _, err := svc.Directory(context.Background(), validSub); !errors.Is(err, publisher.ErrUnavailable) {
		t.Fatalf("Directory err = %v, want ErrUnavailable", err)
	}
}

// A Vault outage must NOT take the revocation list down with the directory. The list
// is pure-Postgres, and an operator can still land a revocation during a Vault outage
// (see lifecycle.Revoker), so a consumer polling the revocation_url has to be able to
// read it back out during the same outage. The directory 503s; the revocation still
// serves, naming the revoked key.
func TestRevocationServedWhileVaultIsDown(t *testing.T) {
	t.Parallel()
	const revoked = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	svc := newSvc(t, publisher.Config{
		Keys:        &stubKeys{err: keystore.ErrUnavailable},
		Cards:       &stubCards{err: directory.ErrCardNotFound},
		Revocations: &stubRevocations{asOf: 123, revoked: []string{revoked}},
	})

	if _, err := svc.Directory(context.Background(), validSub); !errors.Is(err, publisher.ErrUnavailable) {
		t.Fatalf("Directory during a Vault outage = %v, want ErrUnavailable", err)
	}
	body, err := svc.Revocation(context.Background(), validSub)
	if err != nil {
		t.Fatalf("Revocation during a Vault outage = %v, want the list", err)
	}
	if !bytes.Contains(body, []byte(revoked)) {
		t.Errorf("revocation body %q does not name the revoked key %q", body, revoked)
	}
}

// A revocation-store (Postgres) outage surfaces as a 503 on the revocation route,
// never a silently-empty list — an empty list would read to a consumer as "nothing
// revoked" and fail open. Exercises the ErrRevocationUnavailable → ErrUnavailable path.
func TestRevocationUnavailableWhenItsStoreIsDown(t *testing.T) {
	t.Parallel()
	svc := newSvc(t, publisher.Config{
		Keys:        &stubKeys{keys: []keystore.Key{aKey(t)}},
		Cards:       &stubCards{err: directory.ErrCardNotFound},
		Revocations: &stubRevocations{err: directory.ErrRevocationUnavailable},
	})
	if _, err := svc.Revocation(context.Background(), validSub); !errors.Is(err, publisher.ErrUnavailable) {
		t.Fatalf("Revocation with its store down = %v, want ErrUnavailable", err)
	}
}

// The no-cache-on-unavailability guard: a docSet built while a backend was down must
// NOT be pinned in the cache, or the route would keep 503ing (or serving stale partial
// bytes) for the whole TTL after the backend recovered. This asserts the guard by
// recovering the backend and requiring the NEXT request to rebuild and succeed at the
// same instant — removing the `if docs.unavailable()` guard in store() makes it fail,
// because the second request would then return the cached 503.
func TestUnavailableDocSetIsNotCached(t *testing.T) {
	t.Parallel()
	revs := &stubRevocations{err: directory.ErrRevocationUnavailable} // store down
	svc := newSvc(t, publisher.Config{
		Keys:        &stubKeys{keys: []keystore.Key{aKey(t)}},
		Cards:       &stubCards{err: directory.ErrCardNotFound},
		Revocations: revs,
	})

	if _, err := svc.Revocation(context.Background(), validSub); !errors.Is(err, publisher.ErrUnavailable) {
		t.Fatalf("Revocation while its store is down = %v, want ErrUnavailable", err)
	}

	// The store recovers, now reporting a revoked key.
	const revoked = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	revs.err = nil
	revs.asOf = 123
	revs.revoked = []string{revoked}

	// Same instant (no TTL has elapsed): a cached 503 would still fail here, so a
	// rebuilt list proves the unavailable docSet was not pinned.
	body, err := svc.Revocation(context.Background(), validSub)
	if err != nil {
		t.Fatalf("Revocation after its store recovered = %v, want the rebuilt list", err)
	}
	if !bytes.Contains(body, []byte(revoked)) {
		t.Errorf("revocation body %q does not name the revoked key %q", body, revoked)
	}
}

func TestCachedUntilTTLThenRebuilds(t *testing.T) {
	t.Parallel()
	clk := clock.NewDeterministic(anchor)
	keys := &stubKeys{keys: []keystore.Key{aKey(t)}}
	svc := newSvc(t, publisher.Config{Keys: keys, Cards: &stubCards{err: directory.ErrCardNotFound}, TTL: 60 * time.Second, Clock: clk})

	_, _ = svc.Directory(context.Background(), validSub)
	_, _ = svc.Directory(context.Background(), validSub)
	if keys.calls != 1 {
		t.Fatalf("List called %d times within TTL, want 1 (cached)", keys.calls)
	}
	clk.Advance(61 * time.Second)
	_, _ = svc.Directory(context.Background(), validSub)
	if keys.calls != 2 {
		t.Fatalf("List called %d times after TTL, want 2 (rebuilt)", keys.calls)
	}
}

func TestExpiredKeysAreNotPublished(t *testing.T) {
	t.Parallel()
	clk := clock.NewDeterministic(anchor)
	expired := keyWithWindow(t, anchor.AddDate(-2, 0, 0), anchor.AddDate(-1, 0, 0))
	svc := newSvc(t, publisher.Config{
		Keys:  &stubKeys{keys: []keystore.Key{expired}},
		Cards: &stubCards{err: directory.ErrCardNotFound},
		Clock: clk,
	})
	if _, err := svc.Directory(context.Background(), validSub); !errors.Is(err, publisher.ErrAbsent) {
		t.Fatalf("Directory err = %v, want ErrAbsent (only key is out of window)", err)
	}
}

func TestDirectoryCapsAtSchemaMax(t *testing.T) {
	t.Parallel()
	keys := make([]keystore.Key, 65)
	for i := range keys {
		keys[i] = aKey(t)
	}
	svc := newSvc(t, publisher.Config{Keys: &stubKeys{keys: keys}, Cards: &stubCards{err: directory.ErrCardNotFound}})
	body, err := svc.Directory(context.Background(), validSub)
	if err != nil {
		t.Fatalf("Directory with 65 keys: %v (want a truncated directory, not a failure)", err)
	}
	if n := keyCount(t, body); n != 64 {
		t.Fatalf("served %d keys, want 64 (schema max)", n)
	}
}

func TestCacheExpiryClampedToKeyWindow(t *testing.T) {
	t.Parallel()
	clk := clock.NewDeterministic(anchor)
	// Key expires in 60s; TTL is far longer. The entry must expire with the key.
	shortLived := keyWithWindow(t, anchor.Add(-time.Hour), anchor.Add(60*time.Second))
	keys := &stubKeys{keys: []keystore.Key{shortLived}}
	svc := newSvc(t, publisher.Config{Keys: keys, Cards: &stubCards{err: directory.ErrCardNotFound}, TTL: time.Hour, Clock: clk})

	if _, err := svc.Directory(context.Background(), validSub); err != nil {
		t.Fatalf("initial Directory: %v", err)
	}
	clk.Advance(61 * time.Second) // past the key window, well within the TTL
	if _, err := svc.Directory(context.Background(), validSub); !errors.Is(err, publisher.ErrAbsent) {
		t.Fatalf("Directory after key expiry = %v, want ErrAbsent (entry must not outlive the key)", err)
	}
	if keys.calls != 2 {
		t.Fatalf("List called %d times, want 2 (clamped entry forced a rebuild)", keys.calls)
	}
}

func TestNegativeCacheAvoidsRepeatBackendHits(t *testing.T) {
	t.Parallel()
	keys := &stubKeys{} // well-formed unknown host resolves to no keys
	svc := newSvc(t, publisher.Config{Keys: keys, Cards: &stubCards{err: directory.ErrCardNotFound}})
	for range 3 {
		if _, err := svc.Directory(context.Background(), "agent-unknown.rampmcp.org"); !errors.Is(err, publisher.ErrAbsent) {
			t.Fatalf("Directory err = %v, want ErrAbsent", err)
		}
	}
	if keys.calls != 1 {
		t.Fatalf("List called %d times for 3 requests to one unknown host, want 1 (negative cached)", keys.calls)
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	t.Parallel()
	full := func() publisher.Config {
		return publisher.Config{
			Keys: &stubKeys{}, Cards: &stubCards{},
			Revocations: &stubRevocations{}, Registrations: registered(),
		}
	}
	cases := map[string]func(*publisher.Config){
		"Keys":          func(c *publisher.Config) { c.Keys = nil },
		"Cards":         func(c *publisher.Config) { c.Cards = nil },
		"Revocations":   func(c *publisher.Config) { c.Revocations = nil },
		"Registrations": func(c *publisher.Config) { c.Registrations = nil },
	}
	for name, drop := range cases {
		cfg := full()
		drop(&cfg)
		if _, err := publisher.New(cfg); err == nil {
			t.Errorf("New without %s = nil error, want a validation error", name)
		}
	}
	if _, err := publisher.New(full()); err != nil {
		t.Errorf("New with every dependency = %v, want nil", err)
	}
}

func TestBuildDetachesCallerCancellation(t *testing.T) {
	t.Parallel()
	bk := newBlockingKeys([]keystore.Key{aKey(t)})
	svc := newSvc(t, publisher.Config{Keys: bk, Cards: &stubCards{err: directory.ErrCardNotFound}, Clock: clock.System{}})

	callerCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := svc.Directory(callerCtx, validSub)
		done <- err
	}()

	<-bk.started
	cancel() // caller disconnects mid-build

	// The build's own context must NOT be cancelled by the caller — it was detached.
	select {
	case <-bk.gotCtx.Done():
		t.Fatal("build context cancelled by caller: WithoutCancel not applied")
	case <-time.After(100 * time.Millisecond):
	}
	close(bk.release)
	if err := <-done; err != nil {
		t.Fatalf("Directory after caller cancel = %v, want success (peers served despite disconnect)", err)
	}
}

func TestBuildTimesOut(t *testing.T) {
	t.Parallel()
	svc := newSvc(t, publisher.Config{
		Keys:         ctxWaitKeys{},
		Cards:        &stubCards{err: directory.ErrCardNotFound},
		BuildTimeout: 30 * time.Millisecond,
		Clock:        clock.System{},
	})
	if _, err := svc.Directory(context.Background(), validSub); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Directory err = %v, want DeadlineExceeded (a wedged backend must not park forever)", err)
	}
}

func TestInvalidateDuringBuildDropsResult(t *testing.T) {
	t.Parallel()
	bk := newBlockingKeys([]keystore.Key{aKey(t)})
	svc := newSvc(t, publisher.Config{Keys: bk, Cards: &stubCards{err: directory.ErrCardNotFound}, Clock: clock.System{}})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = svc.Directory(context.Background(), validSub) // build 1, blocks below
	}()

	<-bk.started
	svc.Invalidate(validSub) // a rotation bumps the generation mid-build
	close(bk.release)        // build 1 finishes; the generation guard must drop its result
	<-done

	// Nothing was cached, so the next request rebuilds rather than serving the stale doc.
	if _, err := svc.Directory(context.Background(), validSub); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got := bk.callCount(); got != 2 {
		t.Fatalf("List calls = %d, want 2 (build 1 dropped by the generation guard, build 2 rebuilt)", got)
	}
}

func TestInvalidateForcesRebuild(t *testing.T) {
	t.Parallel()
	keys := &stubKeys{keys: []keystore.Key{aKey(t)}}
	svc := newSvc(t, publisher.Config{Keys: keys, Cards: &stubCards{err: directory.ErrCardNotFound}})

	_, _ = svc.Directory(context.Background(), validSub)
	_, _ = svc.Directory(context.Background(), validSub)
	if keys.calls != 1 {
		t.Fatalf("List called %d times, want 1 (cached)", keys.calls)
	}
	svc.Invalidate(validSub)
	_, _ = svc.Directory(context.Background(), validSub)
	if keys.calls != 2 {
		t.Fatalf("List called %d times after Invalidate, want 2", keys.calls)
	}
}

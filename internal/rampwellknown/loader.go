package rampwellknown

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// Default manifest cache TTL and revocation poll cadence. The manifest itself
// rotates slowly (keys carry not_before/not_after), so a multi-minute TTL is
// fine; the revocation snapshot bounds emergency-revocation latency, so it is
// polled on the proto-mandated 300s cadence (±10% jitter).
const (
	DefaultManifestTTL  = time.Hour
	DefaultPollInterval = 300 * time.Second
)

// LoaderOptions configures a Loader.
type LoaderOptions struct {
	// Fetch carries the HTTP client, scheme, port, and timeout used for both
	// manifest and invalidation-list GETs.
	Fetch FetchOptions
	// Clk is the time source for TTL and validity-window comparisons.
	// Defaults to clock.System{}.
	Clk clock.Clock
	// ManifestTTL bounds how long a fetched manifest is reused; default 1h.
	ManifestTTL time.Duration
	// PollInterval is the base revocation-poll cadence; default 300s.
	PollInterval time.Duration
	// Logger receives best-effort revocation-refresh diagnostics.
	Logger *slog.Logger
}

// Loader resolves signing keys published in remote manifests, caching each
// host's manifest for ManifestTTL and tracking the host's revocation snapshot
// (from its invalidation_url) refreshed on a background poll. LookupKey is the
// resolution primitive; Run drives the poller.
type Loader struct {
	store        *manifestStore
	fetch        FetchOptions
	clk          clock.Clock
	manifestTTL  time.Duration
	pollInterval time.Duration
	logger       *slog.Logger

	revMu   sync.RWMutex
	revoked map[string]revocationSet
}

type revocationSet struct {
	kids map[string]struct{}
	asOf time.Time
}

// NewLoader constructs a Loader with defaults applied.
func NewLoader(opts LoaderOptions) *Loader {
	if opts.Clk == nil {
		opts.Clk = clock.System{}
	}
	if opts.ManifestTTL <= 0 {
		opts.ManifestTTL = DefaultManifestTTL
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Loader{
		store:        newManifestStore(opts.Clk),
		fetch:        opts.Fetch,
		clk:          opts.Clk,
		manifestTTL:  opts.ManifestTTL,
		pollInterval: opts.PollInterval,
		logger:       opts.Logger,
		revoked:      map[string]revocationSet{},
	}
}

// LookupKey resolves kid against host's manifest, returning the Ed25519 public
// key when the kid is present, unrevoked, and within its validity window. On an
// unknown kid it performs one bounded manifest re-fetch (rotation self-heal)
// before giving up. Sentinels: ErrKeyRevoked, ErrKeyExpired, ErrKeyUnknown.
//
// A kid merely ABSENT from the manifest (e.g. dropped during rotation) yields
// ErrKeyUnknown, never ErrKeyRevoked: removal is not revocation. The
// authoritative revocation channel is the invalidation list (ADR-003 §5), not
// key omission. A CompositeResolver therefore falls through to its next
// delegate (e.g. the static bootstrap file) on a removed kid — by design.
func (l *Loader) LookupKey(ctx context.Context, host, kid string) (ed25519.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("%w: empty kid", ErrKeyUnknown)
	}
	m, err := l.manifest(ctx, host)
	if err != nil {
		return nil, err
	}
	key, ok := KeyByKid(m, kid)
	if !ok {
		if m, err = l.SyncRefresh(ctx, host); err != nil {
			return nil, err
		}
		if key, ok = KeyByKid(m, kid); !ok {
			return nil, fmt.Errorf("%w: kid=%q host=%q", ErrKeyUnknown, kid, host)
		}
	}
	if l.isRevoked(host, kid) {
		return nil, fmt.Errorf("%w: kid=%q", ErrKeyRevoked, kid)
	}
	if !keyActiveAt(key, l.clk.Now()) {
		return nil, fmt.Errorf("%w: kid=%q", ErrKeyExpired, kid)
	}
	return PublicKey(key)
}

// SyncRefresh force-fetches host's manifest, bypassing the TTL cache, and
// refreshes its revocation snapshot. Bounded by the configured fetch timeout.
func (l *Loader) SyncRefresh(ctx context.Context, host string) (*Manifest, error) {
	m, err := Fetch(ctx, host, l.fetch)
	if err != nil {
		return nil, err
	}
	l.store.put(host, m, l.manifestTTL)
	l.refreshRevocationsFor(ctx, host, m)
	return m, nil
}

// Run drives the revocation poller until ctx is cancelled. Each tick refreshes
// every known host's revocation snapshot on a ±10%-jittered PollInterval.
func (l *Loader) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.clk.After(l.jitteredInterval()):
			l.refreshAllRevocations(ctx)
		}
	}
}

// manifest returns host's cached manifest when fresh, else single-flights a
// fetch, stores it, and primes its revocation snapshot.
func (l *Loader) manifest(ctx context.Context, host string) (*Manifest, error) {
	if m, ok := l.store.get(host); ok {
		return m, nil
	}
	return l.store.single(host, func() (*Manifest, error) {
		m, err := Fetch(ctx, host, l.fetch)
		if err != nil {
			return nil, err
		}
		l.store.put(host, m, l.manifestTTL)
		l.refreshRevocationsFor(ctx, host, m)
		return m, nil
	})
}

func (l *Loader) isRevoked(host, kid string) bool {
	l.revMu.RLock()
	defer l.revMu.RUnlock()
	set, ok := l.revoked[host]
	if !ok {
		return false
	}
	_, revoked := set.kids[kid]
	return revoked
}

// refreshRevocationsFor replaces host's revocation snapshot from m's
// invalidation_url. Best-effort: a fetch failure leaves the prior snapshot in
// place and is logged, never propagated (a stale-but-present snapshot is safer
// than dropping revocations on a transient blip).
func (l *Loader) refreshRevocationsFor(ctx context.Context, host string, m *Manifest) {
	url := m.GetInvalidationUrl()
	if url == "" {
		return
	}
	list, err := l.fetchInvalidation(ctx, url)
	if err != nil {
		l.logger.WarnContext(ctx, "revocation refresh failed",
			"host", host, "invalidation_url", url, "err", err)
		return
	}
	asOf := list.GetAsOf().AsTime()
	set := make(map[string]struct{}, len(list.GetRevoked()))
	for _, kid := range list.GetRevoked() {
		set[kid] = struct{}{}
	}
	l.revMu.Lock()
	prev, ok := l.revoked[host]
	// Monotonic guard: a successful fetch whose as_of is not strictly newer than
	// the snapshot already held is a rollback (stale cache, replayed prior
	// snapshot, regressed document) and is ignored — a revoked kid must not be
	// silently un-revoked. Maps ADR-003 §4 ("generation decrease → reject") onto
	// the proto's as_of timestamp, which stands in for a generation counter.
	rollback := ok && !asOf.After(prev.asOf)
	if !rollback {
		l.revoked[host] = revocationSet{kids: set, asOf: asOf}
	}
	l.revMu.Unlock()
	if rollback {
		l.logger.WarnContext(ctx, "revocation rollback ignored",
			"host", host, "fetched_as_of", asOf, "held_as_of", prev.asOf)
	}
}

func (l *Loader) refreshAllRevocations(ctx context.Context) {
	for _, host := range l.store.hosts() {
		if m, ok := l.store.get(host); ok {
			l.refreshRevocationsFor(ctx, host, m)
		}
	}
}

// fetchInvalidation GETs, schema-validates, and decodes a KeyInvalidationList.
func (l *Loader) fetchInvalidation(ctx context.Context, rawURL string) (*InvalidationList, error) {
	raw, err := getDoc(ctx, l.fetch.client(), rawURL, l.fetch.timeout())
	if err != nil {
		return nil, err
	}
	var list InvalidationList
	if err := decodeValidated(raw, &list, ValidateInvalidation); err != nil {
		return nil, err
	}
	return &list, nil
}

// jitteredInterval returns PollInterval ±10% to avoid synchronized polling.
func (l *Loader) jitteredInterval() time.Duration {
	delta := int64(l.pollInterval) / 10
	if delta <= 0 {
		return l.pollInterval
	}
	//nolint:gosec // G404: poll jitter is not security-sensitive
	jitter := rand.Int64N(2*delta+1) - delta
	return time.Duration(int64(l.pollInterval) + jitter)
}

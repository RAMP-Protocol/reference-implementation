// Package publisher is the Identity Service's service layer: it turns an agent's
// stored keys, card metadata, revocations, and account row into the four documents
// published on its subdomain, caches them per subdomain, and owns presence,
// staleness, and invalidation policy. Transport is a thin HTTP adapter over it;
// the rotation work depends on this package —
// not on transport — for the Invalidate hook, so the dependency runs downward
// (transport → publisher → keystore/repo/directory), never up.
package publisher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

const (
	// DefaultTTL bounds how long a cached document may lag its sources. It must
	// stay well below the rotation overlap window so a rotated key set propagates
	// while the old key still verifies, and it bounds the window in which a freshly
	// written card still 404s (the writer — sign-up — is in another
	// process and cannot reach this process's cache, so a same-process Invalidate is
	// a fast path, not the only path).
	DefaultTTL = 300 * time.Second

	// DefaultNegativeTTL is how long an absent subdomain is remembered so a flood of
	// unknown hosts does not hit the backends every request. Kept short so a newly
	// provisioned agent becomes reachable quickly.
	DefaultNegativeTTL = 30 * time.Second

	// negCacheLimit caps the negative cache so attacker-chosen unknown hosts cannot
	// grow it without bound.
	negCacheLimit = 4096

	// maxDirectoryKeys caps the JWKs a directory publishes, matching the WBA schema's
	// maxItems. Window-filtering makes this practically unreachable; it is a backstop
	// so a pathological key count degrades to a truncated directory, never a build
	// failure that would also take the card down.
	maxDirectoryKeys = 64

	// defaultBuildTimeout bounds a single document build. The build runs on a
	// cancellation-detached context (so a disconnecting caller cannot fail its
	// singleflight peers), which also strips the caller's deadline — this re-imposes
	// one so a wedged backend cannot park the leader and every follower forever.
	defaultBuildTimeout = 5 * time.Second
)

// Sentinels the transport maps to HTTP status. Backend-specific errors are
// translated here so the transport never imports keystore or a driver.
var (
	// ErrAbsent means the requested document does not exist for this subdomain —
	// no keys, no card row, or a malformed host. The transport serves 404.
	ErrAbsent = errors.New("publisher: document absent")
	// ErrUnavailable means a backend could not answer (unreachable, sealed,
	// rate-limited). The transport serves 503; it is the retryable class.
	ErrUnavailable = errors.New("publisher: backend unavailable")
)

// KeySource is the narrow slice of the KeyStore the publisher needs: the published
// keys for one agent, newest-first (order is load-bearing). *keystore.VaultStore
// satisfies it.
type KeySource interface {
	List(ctx context.Context, subdomain string) ([]keystore.Key, error)
}

// Config wires a Service. Keys, Cards, Revocations, and Registrations are required;
// the rest take defaults.
type Config struct {
	Keys          KeySource
	Cards         directory.CardReader
	Revocations   directory.RevocationReader
	Registrations Registrations
	// WellKnownScheme is the URL scheme used to build the per-subdomain
	// revocation_url advertised in each agent's directory
	// (<scheme>://<subdomain>/.well-known/ramp-key-revocations.json). It is
	// deploy-aware — "https" in production, "http" for a local/compose e2e stack —
	// and defaults to "https". The advertised URL is always same-host with the
	// directory, because a consumer host-anchors it and skips a cross-host one; a
	// single shared URL would therefore leave every other agent's list unpolled.
	WellKnownScheme string
	TTL             time.Duration
	NegativeTTL     time.Duration
	BuildTimeout    time.Duration
	Clock           clock.Clock
}

// Service builds, caches, and serves an agent's documents by subdomain.
type Service struct {
	keys          KeySource
	cards         directory.CardReader
	revocations   directory.RevocationReader
	registrations Registrations
	scheme        string // URL scheme for each agent's advertised, host-anchored revocation_url
	ttl           time.Duration
	clock         clock.Clock

	buildTimeout time.Duration

	positive sync.Map // subdomain -> *entry
	negative *negCache
	group    singleflight.Group

	genMu sync.Mutex
	gen   map[string]uint64 // subdomain -> invalidation generation
}

// New builds a Service, applying defaults for TTL, NegativeTTL, and Clock. It fails
// if a required dependency is missing rather than nil-panicking on the first request.
func New(cfg Config) (*Service, error) {
	if cfg.Keys == nil {
		return nil, errors.New("publisher: Config.Keys is required")
	}
	if cfg.Cards == nil {
		return nil, errors.New("publisher: Config.Cards is required")
	}
	if cfg.Revocations == nil {
		return nil, errors.New("publisher: Config.Revocations is required")
	}
	if cfg.Registrations == nil {
		return nil, errors.New("publisher: Config.Registrations is required")
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	negTTL := cfg.NegativeTTL
	if negTTL <= 0 {
		negTTL = DefaultNegativeTTL
	}
	buildTimeout := cfg.BuildTimeout
	if buildTimeout <= 0 {
		buildTimeout = defaultBuildTimeout
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	scheme := cfg.WellKnownScheme
	if scheme == "" {
		scheme = "https"
	}
	return &Service{
		keys:          cfg.Keys,
		cards:         cfg.Cards,
		revocations:   cfg.Revocations,
		registrations: cfg.Registrations,

		scheme:       scheme,
		ttl:          ttl,
		clock:        clk,
		buildTimeout: buildTimeout,
		negative:     newNegCache(negTTL, negCacheLimit, clk),
		gen:          make(map[string]uint64),
	}, nil
}

// Directory returns the WBA JWK Set for subdomain, or ErrAbsent when the agent has
// no currently-valid keys and ErrUnavailable when a backend is down.
func (s *Service) Directory(ctx context.Context, subdomain string) ([]byte, error) {
	return s.pick(ctx, subdomain, func(d *docSet) ([]byte, bool) { return d.wba, d.wbaUnavail })
}

// Card returns the Signature Agent Card JSON for subdomain, or ErrAbsent when no
// card row exists.
func (s *Service) Card(ctx context.Context, subdomain string) ([]byte, error) {
	return s.pick(ctx, subdomain, func(d *docSet) ([]byte, bool) { return d.card, d.cardUnavail })
}

// Revocation returns the KeyRevocationList JSON served at the agent's revocation_url.
// An agent with a directory gets the list (the epoch baseline when nothing is
// revoked); an agent whose directory has gone absent but which still has revoked keys
// keeps getting the real list, so a consumer holding a cached directory learns those
// keys are dead. Only a wholly-unknown subdomain — no directory, nothing revoked — is
// ErrAbsent (404).
func (s *Service) Revocation(ctx context.Context, subdomain string) ([]byte, error) {
	return s.pick(ctx, subdomain, func(d *docSet) ([]byte, bool) { return d.revocation, d.revUnavail })
}

// Invalidate drops a subdomain's cached documents and bumps its generation so a
// build that started before this call cannot store a stale document over it — the
// same-process fast path the rotation work triggers after a key change.
// Cross-process staleness is bounded by the TTL regardless.
func (s *Service) Invalidate(subdomain string) {
	s.genMu.Lock()
	s.gen[subdomain]++
	s.genMu.Unlock()
	s.positive.Delete(subdomain)
	s.negative.delete(subdomain)
}

// pick resolves one document by subdomain: present bytes are served, a nil document
// whose backend was down is ErrUnavailable (503), and a nil document that is simply
// absent is ErrAbsent (404). Telling the two apart is what lets one backend's outage
// 503 only the documents it owns.
func (s *Service) pick(
	ctx context.Context, subdomain string, sel func(*docSet) (body []byte, unavail bool),
) ([]byte, error) {
	docs, err := s.get(ctx, subdomain)
	if err != nil {
		return nil, err
	}
	body, unavail := sel(docs)
	switch {
	case body != nil:
		return body, nil
	case unavail:
		return nil, ErrUnavailable
	default:
		return nil, ErrAbsent
	}
}

// get returns the cached documents for subdomain, building them on first use or
// after the TTL expires. A malformed host is rejected before any backend round-trip;
// a well-formed-but-unknown host is remembered in the bounded negative cache so a
// flood of them costs one backend round-trip apiece, not one every request.
// Concurrent first-builds for one subdomain collapse via singleflight.
func (s *Service) get(ctx context.Context, subdomain string) (*docSet, error) {
	if !keystore.ValidSubdomain(subdomain) {
		return &docSet{}, nil
	}
	if docs, ok := s.loadPositive(subdomain); ok {
		return docs, nil
	}
	if s.negative.has(subdomain) {
		return &docSet{}, nil
	}
	v, err, _ := s.group.Do(subdomain, func() (any, error) {
		if docs, ok := s.loadPositive(subdomain); ok {
			return docs, nil
		}
		if s.negative.has(subdomain) {
			return &docSet{}, nil
		}
		gen := s.readGen(subdomain)
		// Detach the first caller's cancellation so a disconnect cannot fail the
		// peers collapsed into this build, then re-impose a deadline of our own.
		bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.buildTimeout)
		defer cancel()
		docs, buildErr := s.build(bctx, subdomain)
		if buildErr != nil {
			return nil, buildErr
		}
		s.store(subdomain, docs, gen)
		return docs, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*docSet), nil
}

// loadPositive returns a live (unexpired) cached docSet, treating an expired entry
// as a miss.
func (s *Service) loadPositive(subdomain string) (*docSet, bool) {
	e, ok := s.positive.Load(subdomain)
	if !ok {
		return nil, false
	}
	ent := e.(*entry)
	if !s.clock.Now().Before(ent.expires) {
		return nil, false
	}
	return ent.docs, true
}

// store caches the built documents unless an Invalidate raced this build (the
// generation moved), in which case the result is dropped so the next request
// rebuilds. An absent agent goes in the negative cache; a present one in the
// positive cache with its expiry clamped to the earliest key NotAfter.
func (s *Service) store(subdomain string, docs *docSet, gen uint64) {
	s.genMu.Lock()
	defer s.genMu.Unlock()
	if s.gen[subdomain] != gen {
		return
	}
	if docs.unavailable() {
		return // a backend was down; don't pin a partial answer for the TTL — retry next request
	}
	if docs.empty() {
		s.negative.put(subdomain)
		return
	}
	expires := s.clock.Now().Add(s.ttl)
	if !docs.keyExpiry.IsZero() && docs.keyExpiry.Before(expires) {
		expires = docs.keyExpiry
	}
	s.positive.Store(subdomain, &entry{docs: docs, expires: expires})
}

func (s *Service) readGen(subdomain string) uint64 {
	s.genMu.Lock()
	defer s.genMu.Unlock()
	return s.gen[subdomain]
}

// build assembles the four published documents from their own sources. A backend
// outage for ONE document does not sink the others — it is recorded as that document's
// unavailability and the pass continues — so a Vault outage still yields the
// Postgres-backed revocation list, which is exactly the moment an operator's revocation
// needs to be readable. Only a hard fault (a corrupt record, a marshal failure) fails
// the whole build; a build that carries any unavailability is served per-route but not
// cached (see store).
func (s *Service) build(ctx context.Context, subdomain string) (*docSet, error) {
	ds := &docSet{}
	unavail, err := s.buildWBA(ctx, subdomain, ds)
	if err != nil {
		return nil, err
	}
	ds.wbaUnavail = unavail

	unavail, err = s.buildCard(ctx, subdomain, ds)
	if err != nil {
		return nil, err
	}
	ds.cardUnavail = unavail

	// Serve the revocation list whenever the agent has a directory advertising its
	// revocation_url OR has anything revoked to report — the latter so a consumer still
	// holding a cached directory learns a key is dead even after the agent's last key
	// was destroyed and the directory itself went absent.
	unavail, err = s.buildRevocation(ctx, subdomain, ds)
	if err != nil {
		return nil, err
	}
	ds.revUnavail = unavail

	// The overlay reads only the account row, so its presence does not depend on any
	// document built above and this call may sit anywhere in the pass.
	unavail, err = s.buildManifest(ctx, subdomain, ds)
	if err != nil {
		return nil, err
	}
	ds.manifestUnavail = unavail
	return ds, nil
}

// buildWBA sets ds.wba, or reports (unavailable) when Vault is down, or leaves it
// absent. It never returns ErrUnavailable up the stack — availability is the caller's
// per-document concern now — only a hard fault (a bad revocation URL, a marshal error).
func (s *Service) buildWBA(ctx context.Context, subdomain string, ds *docSet) (bool, error) {
	keys, err := s.keys.List(ctx, subdomain)
	switch {
	case err == nil:
		active := s.activeKeys(keys)
		if len(active) == 0 {
			return false, nil // no currently-valid key — the directory is absent (404)
		}
		// Advertise this agent's OWN revocation list, on its own host. The consumer
		// host-anchors revocation_url to the directory host and skips a cross-host
		// one, so the URL must be derived per subdomain, never a shared static value.
		revURL, urlErr := rampwellknown.RevocationURL(subdomain, s.scheme, "")
		if urlErr != nil {
			return false, fmt.Errorf("publisher: revocation url for %q: %w", subdomain, urlErr)
		}
		wba, buildErr := directory.BuildWBA(active, revURL)
		if buildErr != nil {
			return false, buildErr
		}
		ds.wba = wba
		ds.keyExpiry = earliestNotAfter(active)
		return false, nil
	case errors.Is(err, keystore.ErrNotFound), errors.Is(err, keystore.ErrInvalidSubdomain):
		return false, nil
	case errors.Is(err, keystore.ErrUnavailable), errors.Is(err, keystore.ErrPermissionDenied):
		return true, nil // Vault down — the directory route 503s, its siblings do not
	default:
		return false, err
	}
}

func (s *Service) buildCard(ctx context.Context, subdomain string, ds *docSet) (bool, error) {
	card, err := s.cards.BySubdomain(ctx, subdomain)
	switch {
	case err == nil:
		raw, buildErr := directory.BuildCard(card)
		if buildErr != nil {
			return false, buildErr
		}
		ds.card = raw
		return false, nil
	case errors.Is(err, directory.ErrCardNotFound):
		return false, nil
	case errors.Is(err, directory.ErrCardUnavailable):
		return true, nil
	default:
		return false, err
	}
}

// buildRevocation assembles the KeyRevocationList from the registry's as_of and
// revoked set. A subdomain with no revocation row yields the epoch baseline, not an
// error; only a genuine store outage reports (unavailable). It reads ONLY Postgres, so
// it stays available during a Vault outage — even a directory that has gone unavailable
// (ds.wba nil) still yields the revocation list whenever there is anything revoked.
func (s *Service) buildRevocation(ctx context.Context, subdomain string, ds *docSet) (bool, error) {
	asOf, revoked, err := s.revocations.BySubdomain(ctx, subdomain)
	if err != nil {
		if errors.Is(err, directory.ErrRevocationUnavailable) {
			return true, nil
		}
		return false, err
	}
	// A wholly-unknown subdomain — no directory to advertise a revocation_url, nothing
	// revoked — has no revocation channel, so it stays absent (and routes to the
	// negative cache). Everything else serves a list: the epoch baseline when a
	// directory exists but nothing is revoked, the real snapshot otherwise.
	if ds.wba == nil && asOf == 0 && len(revoked) == 0 {
		return false, nil
	}
	raw, buildErr := directory.BuildRevocation(time.Unix(0, asOf).UTC(), revoked)
	if buildErr != nil {
		return false, buildErr
	}
	ds.revocation = raw
	return false, nil
}

// activeKeys keeps the keys whose validity window covers now, in the input's
// newest-first order, capped at maxDirectoryKeys. Presence in the directory is the
// validity statement a generic WBA verifier reads, so an out-of-window key must not
// be published; the store returns every held key, so the window filter lives here.
func (s *Service) activeKeys(keys []keystore.Key) []keystore.Key {
	now := s.clock.Now()
	active := make([]keystore.Key, 0, len(keys))
	for _, k := range keys {
		if !now.Before(k.Window.NotBefore) && now.Before(k.Window.NotAfter) {
			active = append(active, k)
			if len(active) == maxDirectoryKeys {
				break
			}
		}
	}
	return active
}

// earliestNotAfter returns the soonest NotAfter among keys, which must be non-empty.
func earliestNotAfter(keys []keystore.Key) time.Time {
	earliest := keys[0].Window.NotAfter
	for _, k := range keys[1:] {
		if k.Window.NotAfter.Before(earliest) {
			earliest = k.Window.NotAfter
		}
	}
	return earliest
}

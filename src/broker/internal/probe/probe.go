// Package probe adapts a per-Broker-instance rampwellknown.Cache to the
// Broker's pre-existing Probe API.
//
// v1 requires every publisher to host /.well-known/ramp.json. The probe
// surfaces two typed error shapes — ErrManifestMissing (the domain
// returned 404 / no manifest) and ErrProbeFailed (transient fetch,
// decode, or non-2xx failures). Callers MUST refuse the request with
// the appropriate canonical absence vocabulary; the broker no longer
// silently accepts an unmanifested publisher.
package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// DefaultTTL mirrors rampwellknown.DefaultCacheTTL for callers depending on
// this symbol.
const DefaultTTL = rampwellknown.DefaultCacheTTL

// AuthorizedExchange is one Exchange the publisher authorizes. The field name
// is kept for backwards compatibility with existing call sites; wire format
// matches the manifest's exchanges[] entries (domain/endpoint/relationship).
type AuthorizedExchange struct {
	Domain            string
	Endpoint          string
	SupportedProfiles []string
}

// Manifest is the Broker's narrow projection of a publisher manifest. It
// carries only the fields the routing code consults.
type Manifest struct {
	Ver       string
	Provider  string
	Exchanges []AuthorizedExchange
}

// Result carries a successfully fetched manifest. Probe returns a typed
// error (ErrManifestMissing, ErrProbeFailed, ErrInvalidDomain) when the
// domain has no usable manifest; on the error paths Result is zero-valued.
type Result struct {
	Manifest  Manifest
	FetchedAt time.Time
}

// ErrInvalidDomain is returned for empty or obviously invalid input.
var ErrInvalidDomain = errors.New("probe: invalid domain")

// ErrManifestMissing is returned when the publisher's /.well-known/ramp.json
// is absent (404 / explicit no-manifest). v1 requires every publisher to
// host ramp.json; callers MUST refuse with the NOT_IN_CATALOG absence
// reason rather than retry the bare URL.
var ErrManifestMissing = errors.New("probe: publisher does not host ramp.json")

// ErrProbeFailed wraps a transient fetch / decode / non-2xx failure.
// Callers MUST refuse with the TEMPORARILY_UNAVAILABLE absence reason —
// the probe is not authoritative about catalog membership when the
// upstream is unreachable.
var ErrProbeFailed = errors.New("probe: ramp.json fetch failed")

// HTTPDoer is the minimal interface the Prober needs from an *http.Client.
type HTTPDoer = rampwellknown.HTTPDoer

// Options tunes the Prober.
type Options struct {
	TTL     time.Duration
	Timeout time.Duration
	Scheme  string
	// Clk is the time source consulted to stamp Result.FetchedAt on the
	// success path and to drive the shared cache's TTL comparisons.
	// Defaults to clock.System{}.
	Clk clock.Clock
}

// manifestGetter is the narrow read the Prober needs from the shared
// rampwellknown.Cache: fetch a host's publisher manifest, surfacing 404 as
// rampwellknown.ErrNoManifest. *rampwellknown.Cache satisfies it.
type manifestGetter interface {
	Get(ctx context.Context, host string) (*rampwellknown.Manifest, error)
}

// Prober is a thin adapter over rampwellknown.Cache that translates
// ErrNoManifest / fetch failures into the typed ErrManifestMissing /
// ErrProbeFailed surface the Broker resolve handler refuses on.
type Prober struct {
	cache  manifestGetter
	logger *slog.Logger
	clk    clock.Clock
}

// New constructs a Prober backed by a fresh in-process rampwellknown.Cache.
// ExpectRole pins fetched manifests to ROLE_PUBLISHER so a misrouted document
// is rejected before routing. To share one Cache across Probers in the same
// process, construct the Cache directly and use NewFromCache instead.
func New(client HTTPDoer, logger *slog.Logger, opts Options) *Prober {
	if client == nil {
		// Fail safe: an omitted client gets the SSRF-guarded env client
		// (mirroring rampwellknown.NewCache), never the unguarded
		// http.DefaultClient.
		client = rampwellknown.NewGuardedClientFromEnv()
	}
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Clk == nil {
		opts.Clk = clock.System{}
	}
	cache := rampwellknown.NewCache(rampwellknown.CacheOptions{
		Client:     client,
		Scheme:     opts.Scheme,
		TTL:        opts.TTL,
		Timeout:    opts.Timeout,
		Clk:        opts.Clk,
		ExpectRole: rampwellknown.RolePublisher,
	})
	return &Prober{cache: cache, logger: logger, clk: opts.Clk}
}

// NewFromCache wires a Prober onto an externally-owned Cache so Broker and
// Exchange can share one rampwellknown.Cache instance. clk drives the
// FetchedAt stamp on the success path; pass clock.System{} in production.
func NewFromCache(cache *rampwellknown.Cache, logger *slog.Logger, clk clock.Clock) *Prober {
	if logger == nil {
		logger = slog.Default()
	}
	if clk == nil {
		clk = clock.System{}
	}
	return &Prober{cache: cache, logger: logger, clk: clk}
}

// Probe returns the publisher manifest for a domain, fetching or hitting
// cache as needed. The success path returns the manifest with a zero
// error. A domain that does not host ramp.json yields
// (Result{}, ErrManifestMissing); a transient fetch / decode / non-2xx
// failure (rampwellknown ErrFetch / ErrSchemaInvalid / ErrRoleMismatch)
// yields (Result{}, ErrProbeFailed) wrapping the underlying cause.
func (p *Prober) Probe(ctx context.Context, domain string) (Result, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return Result{}, ErrInvalidDomain
	}
	m, err := p.cache.Get(ctx, domain)
	switch {
	case err == nil:
		return Result{
			Manifest:  toBrokerManifest(m),
			FetchedAt: p.clk.Now(),
		}, nil
	case errors.Is(err, rampwellknown.ErrNoManifest):
		return Result{}, ErrManifestMissing
	default:
		p.logger.InfoContext(ctx, "ramp.json probe failed",
			"domain", domain, "err", err)
		return Result{}, fmt.Errorf("%w: %w", ErrProbeFailed, err)
	}
}

func toBrokerManifest(m *rampwellknown.Manifest) Manifest {
	if m == nil {
		return Manifest{}
	}
	out := Manifest{
		Ver:       m.GetVer(),
		Provider:  m.GetDomain(),
		Exchanges: make([]AuthorizedExchange, 0, len(m.GetExchanges())),
	}
	for _, ex := range m.GetExchanges() {
		out.Exchanges = append(out.Exchanges, AuthorizedExchange{
			Domain:   ex.GetDomain(),
			Endpoint: ex.GetEndpoint(),
			// Supported profiles are a manifest-level field; forward them
			// unchanged per Exchange entry so Broker routing keeps working
			// without a schema rev of the broker's view.
			SupportedProfiles: m.GetSupportedProfiles(),
		})
	}
	return out
}

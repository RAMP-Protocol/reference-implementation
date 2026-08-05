// Package agentkeys resolves an unknown signer's transport-signing key from the
// signer's own Web Bot Auth directory, backing the Exchange/Broker httpsig
// middleware's per-agent fallback (ADR-009 D3/D4).
//
// After the WBA split the RFC 9421 keyid is the RFC 7638 thumbprint of the
// signing key (proof of key possession), no longer the signer's domain. The
// signer names its own directory origin in the covered Signature-Agent header;
// the verifier threads that origin into the resolver context
// (helpers.WithSignatureAgent). This resolver hands it to the SDK's
// WBAKeyResolver, which fetches that origin's WBA directory (through the
// injected SSRF-guarded client, TTL-cached) and matches the incoming thumbprint
// against the directory's locally-computed key thumbprints. A never-before-seen
// signer authenticates at the transport layer this way, so the service can
// lazy-register it (service.resolveAgentLazily) keyed on the Signature-Agent
// domain.
//
// The directory is cached (TTL) because a signer's key is re-resolved here on
// every request — caching is what keeps that from issuing one outbound fetch
// per request.
package agentkeys

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// Config wires the per-agent resolver.
type Config struct {
	// Client is the SSRF-guarded HTTP client for WBA-directory fetches. The
	// directory origin is attacker-influenced (it arrives in a request header),
	// so this MUST be guarded and is REQUIRED: the caller constructs it once from
	// resolvers.NewGuardedClientFromEnv at its composition root and injects it
	// (this package never re-wraps the SDK factory as an in-constructor default).
	// Concrete *http.Client because it feeds the SDK's resolvers.WBAKeyResolver,
	// whose HTTP option is a concrete *http.Client.
	Client *http.Client
	// Scheme/Port shape the WBA-directory URL for bare-host Signature-Agent
	// origins on local/compose stacks (RAMP_WELLKNOWN_{SCHEME,PORT}); empty
	// means https + default port.
	Scheme string
	Port   string
	// TTL bounds how long a fetched WBA directory is cached; 0 uses the SDK
	// resolver default.
	TTL time.Duration
	// PollInterval is the revocation-refresh cadence for the background poller
	// started on the resolver's lifecycle context; 0 uses the SDK default
	// (300s). Bounds how long a key revoked after first contact keeps verifying.
	PollInterval time.Duration
	// Clk is the validity-window + cache-TTL time source; nil uses clock.System{}.
	Clk clock.Clock
	// Logger receives best-effort miss diagnostics; nil uses slog.Default().
	Logger *slog.Logger
	// OnPollArmed and OnPollCycle are optional determinism seams forwarded to
	// the SDK resolver's poller (nil in production); see
	// resolvers.WBAKeyResolverOptions for the contract. A deterministic-clock test
	// uses them to cross a revocation-poll boundary without sleeping.
	OnPollArmed func()
	OnPollCycle func()
}

// New returns a helpers.KeyResolver that resolves a thumbprint keyid by
// fetching the signer's WBA directory (named by the signed Signature-Agent
// header on the request context) and matching the thumbprint against it. It
// reports helpers.ErrUnknownKey for a missing Signature-Agent and for ANY
// fetch/parse/thumbprint-mismatch/revocation/expiry failure, so a
// keypolicy.CompositeResolver treats a miss as "not my key" and falls through
// cleanly. That masking is deliberate app policy (the SDK surfaces
// revoked/expired/unavailable verdicts raw and leaves the decision to the
// caller): this resolver sits LAST in the composite, where a miss of any kind
// means "try lazy registration".
//
// ctx is the resolver's lifecycle context: New starts the SDK
// resolver's revocation poller on it (go r.Run(ctx)) so each resolved signer's
// revocation snapshot refreshes on the poll cadence. Without the poller a key
// revoked after first contact would keep verifying until the directory TTL
// forced a re-fetch; the poller bounds that to the poll interval. Cancel ctx to
// stop the poller. Mirrors brokerRevocationResolver.
func New(ctx context.Context, cfg Config) helpers.KeyResolver {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clk := cfg.Clk
	if clk == nil {
		clk = clock.System{}
	}
	resolver := keypolicy.RunningWBAResolver(ctx, resolvers.WBAKeyResolverOptions{
		HTTP:         cfg.Client,
		TTL:          cfg.TTL,
		PollInterval: cfg.PollInterval,
		Now:          clk.Now,
		After:        clk.After,
		Scheme:       cfg.Scheme,
		Logger:       logger,
		OnPollArmed:  cfg.OnPollArmed,
		OnPollCycle:  cfg.OnPollCycle,
	})
	return keypolicy.ResolverFunc(func(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
		raw := helpers.SignatureAgentFromContext(ctx)
		if raw == "" || keyID == "" {
			return nil, fmt.Errorf("%w: no Signature-Agent directory for keyid=%q", helpers.ErrUnknownKey, keyID)
		}
		// Canonicalize before the fetch, for the same reason agentreg keys its
		// refresh debounce on the canonical host: the SDK's directory cache keys on
		// the host exactly as parsed, so "a.example", "A.Example", "a.example." and
		// "a.example:443" would be four cache entries and four outbound fetches per
		// TTL window — one budget per spelling a caller can invent, on the path that
		// runs for every request and before agentreg is reached.
		//
		// Authorization is unaffected either way: the thumbprint still has to appear
		// in whatever directory is fetched. What changes is the fetch budget and the
		// cache.
		directory, err := agentid.FromDirectory(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: signature-agent %q does not name a host: %w",
				helpers.ErrUnknownKey, raw, err)
		}
		shaped := withConfiguredPort(directory, cfg.Port)
		pub, err := resolver.Resolve(helpers.WithSignatureAgent(ctx, shaped), keyID)
		if err != nil {
			// Absent directory / unreachable / thumbprint-mismatch / revoked /
			// expired all mean "cannot verify against this signer's published
			// key": report unknown so the composite exhausts to ErrUnknownKey
			// (→ 401).
			// Request-scoped logger so the auth-miss line carries request_id (the
			// resolver runs only on the request path). Falls back to the default
			// logger when no request context is present.
			reqctx.FromContext(ctx).DebugContext(ctx, "agent WBA key resolution miss",
				"keyid", keyID, "directory", shaped, "err", err)
			return nil, fmt.Errorf("%w: keyid=%q at %q: %w", helpers.ErrUnknownKey, keyID, shaped, err)
		}
		return pub, nil
	})
}

// NewFromEnv builds the per-agent WBA key resolver from the process environment:
// it reads the RAMP_WELLKNOWN_SCHEME + RAMP_WELLKNOWN_PORT knobs that shape
// bare-host Signature-Agent directory URLs on local/compose stacks and threads
// the shared fetch client + logger. Broker and Exchange share this
// construction. A wiring change (a knob rename, an env-defaulted TTL) now
// lands here once instead of drifting between services.
func NewFromEnv(ctx context.Context, fetch *http.Client, logger *slog.Logger) helpers.KeyResolver {
	return New(ctx, Config{
		Client: fetch,
		Scheme: runhttp.EnvOr("RAMP_WELLKNOWN_SCHEME", "https"),
		Port:   runhttp.EnvOr("RAMP_WELLKNOWN_PORT", ""),
		Logger: logger,
	})
}

// withConfiguredPort appends the configured fetch port to a bare-host
// Signature-Agent origin (compose stacks name services by bare host). An origin
// that already carries a scheme or a port is left untouched.
func withConfiguredPort(directory, port string) string {
	if port == "" || strings.Contains(directory, "://") || strings.Contains(directory, ":") {
		return directory
	}
	return directory + ":" + port
}

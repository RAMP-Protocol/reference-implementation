// Package offerkeys resolves a registered exchange DOMAIN to that exchange's
// Ed25519 OFFER-SIGNING key, backing the Broker's client-side offer Verifier
// (sdk/go/core.Verifier) on the typed discover path.
//
// After the WBA split the offer-signing key lives ONLY in the exchange's Web
// Bot Auth directory at /.well-known/http-message-signatures-directory (see
// src/exchange/internal/wellknown — the exchange publishes exactly that key
// there); it is NOT in ramp.json. The SDK Verifier resolves by
// Offer.GetExchange() — a domain — so this resolver is domain-keyed, unlike
// resolvers.WBAKeyResolver (thumbprint-keyed off the Signature-Agent header,
// the inbound-request identity face).
//
// The per-domain TTL cache -> active-key selection -> not_after clamp is the
// SDK's resolvers.CachedOfferKeyResolver: this package is a thin composition
// root that injects the broker's collaborators (the SSRF-guarded WBA fetch, the
// injected clock, the revocation-screen predicate) and keeps the broker's
// New/Config contract stable for the Verifier wiring. The clamp and the
// off-by-one-prone min(now+ttl, not_after) live once in the SDK.
//
// The directory is fetched through the injected client (the same SSRF-guarded
// client the rest of the broker's well-known fetching uses — exchange domains
// come from the trusted registry allowlist, but the guard costs nothing).
// Rotation caveat: KeyResolver returns ONE key, so during a dual-key rotation
// grace window offers signed by the newer active key resolve only once the older
// key leaves the directory (or drops out of document order) — acceptable for the
// current single-key exchanges and recorded on the SDK-gap ticket alongside the
// other Verifier seam work.
package offerkeys

import (
	"context"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// Config wires the resolver.
type Config struct {
	// Client is the HTTP client for WBA-directory fetches. It is REQUIRED: the
	// SSRF guard is SDK-owned, so the composition root constructs the guarded
	// client once (resolvers.NewGuardedClientFromEnv) and injects it here. A nil
	// Client is a fail-loud rampwellknown.ErrNoClient — this package never
	// fabricates a fail-open default (matching agentkeys and rampwellknown).
	//
	// Typed rampwellknown.HTTPDoer (an interface) rather than agentkeys' concrete
	// *http.Client on purpose: this Client feeds rampwellknown.FetchWBA, whose
	// option IS an HTTPDoer, and the broker's discover integration test injects a
	// request-rewriting HTTPDoer double (rewritingHTTPClient) here to route WBA
	// fetches at a local httptest server. agentkeys stays concrete because its
	// Client feeds the SDK's resolvers.WBAKeyResolver, whose HTTP option is a
	// concrete *http.Client — the two types differ because their sinks differ.
	Client rampwellknown.HTTPDoer
	// Scheme/Port shape the directory URL for bare-host domains on
	// local/compose stacks (mirror RAMP_WELLKNOWN_SCHEME); empty means https
	// + default port.
	Scheme string
	Port   string
	// TTL bounds the per-domain cache; <=0 uses the SDK default.
	TTL time.Duration
	// Clk is the cache-freshness + key-validity time source; nil uses clock.System.
	Clk clock.Clock
	// Revoked screens a candidate exchange offer-signing key by its RFC 7638
	// thumbprint, so a window-active-but-revoked key still listed in a CDN-cached
	// directory is never served on this verification path. nil installs an explicit
	// nothing-revoked predicate: the Broker only RELAYS offers (it never terminates
	// a transaction) and holds no exchange revocation channel, so the terminal
	// checkpoint that consults revocation is the Exchange — the same relay-only
	// revocation stance the agent-sig resolver documents. The explicit waiver keeps
	// that a visible decision rather than a silent nil.
	Revoked func(thumbprint string) bool
}

// Resolver is the broker's offer-key resolver type: the SDK CachedOfferKeyResolver
// keyed by exchange DOMAIN. It is an alias, not a wrapper — the per-domain TTL
// cache, active-key selection, and not_after clamp all live in the SDK; this
// package only supplies the broker's collaborators at construction (New). The alias
// keeps the broker's public type name stable for the Verifier wiring and fixtures.
type Resolver = resolvers.CachedOfferKeyResolver

// New builds the SDK CachedOfferKeyResolver wired with the broker's guarded WBA
// fetch, injected clock, and revocation-screen predicate. It implements
// helpers.KeyResolver keyed by exchange DOMAIN, the shape core.Verifier resolves
// offer keys through, so the returned resolver drops straight into the Verifier
// wiring.
func New(cfg Config) *Resolver {
	clk := cfg.Clk
	if clk == nil {
		clk = clock.System{}
	}
	revoked := cfg.Revoked
	if revoked == nil {
		revoked = func(string) bool { return false }
	}
	fetch := func(ctx context.Context, domain string) (*rampwellknown.WBAFile, error) {
		return rampwellknown.FetchWBA(ctx, domain, rampwellknown.FetchOptions{
			Client: cfg.Client,
			Scheme: cfg.Scheme,
			Port:   cfg.Port,
		})
	}
	return resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{
		Fetch:   fetch,
		TTL:     cfg.TTL,
		Now:     clk.Now,
		Revoked: revoked,
	})
}

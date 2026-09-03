// Package offerkeys resolves an exchange DOMAIN to that exchange's Ed25519
// OFFER-SIGNING key, backing a client-side offer Verifier (sdk/go/core.Verifier)
// wherever offers arrive from a party that did not mint them.
//
// It sits in shared internal code because two services need the same answer. The
// Broker verifies the offers it relays on the typed discover path. The identity
// service verifies the offers it hands an SDK-less agent, which is the same
// question asked one hop further along — an agent reached through the MCP surface
// runs no verifier of its own, so the registry is the only place the check can
// happen on its behalf.
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
// root that injects each caller's collaborators (the SSRF-guarded WBA fetch, the
// injected clock, the revocation-screen predicate) behind one New/Config contract
// for the Verifier wiring. The clamp and the off-by-one-prone
// min(now+ttl, not_after) live once in the SDK.
//
// The domain is checked to be a plain host before anything is fetched, and that
// is a separate control from the SSRF guard rather than a duplicate of it. The
// guard bounds the ADDRESS this resolver may dial; it says nothing about the
// path. The directory URL is built by concatenating this value, so a domain
// carrying a path, query or fragment picks the URL that gets fetched and not
// merely the host it is fetched from — one blind caller-chosen GET per offer in
// a discovery response. The identity service reaches here with a value taken off
// an offer a Broker relayed, which is exactly a value nobody has vetted: the
// fetch happens in order to verify that offer, so it cannot have been verified
// first. The SDK applies the same check on its own routing path and says why —
// a package that owns the call cannot assume every present and future caller
// vetted the input.
//
// Rotation caveat: KeyResolver returns ONE key, so during a dual-key rotation
// grace window offers signed by the newer active key resolve only once the older
// key leaves the directory (or drops out of document order) — acceptable for the
// current single-key exchanges and recorded on the SDK-gap ticket alongside the
// other Verifier seam work.
package offerkeys

import (
	"context"
	"fmt"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
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
	// option IS an HTTPDoer, and the Broker's discover integration test injects a
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
	// nothing-revoked predicate, and both callers take that waiver on the same
	// grounds: each only RELAYS offers — neither terminates a transaction — and
	// neither holds an exchange revocation channel, so the terminal checkpoint that
	// consults revocation is the Exchange. That is the same relay-only revocation
	// stance the agent-sig resolver documents. The explicit waiver keeps it a
	// visible decision rather than a silent nil.
	Revoked func(thumbprint string) bool
}

// Resolver is the offer-key resolver type: the SDK CachedOfferKeyResolver keyed
// by exchange DOMAIN. It is an alias, not a wrapper — the per-domain TTL cache,
// active-key selection, and not_after clamp all live in the SDK; this package
// only supplies each caller's collaborators at construction (New). The alias
// keeps one stable name for the Verifier wiring and the fixtures.
type Resolver = resolvers.CachedOfferKeyResolver

// New builds the SDK CachedOfferKeyResolver wired with the caller's guarded WBA
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
		if err := vetDomain(domain); err != nil {
			return nil, err
		}
		dir, err := rampwellknown.FetchWBA(ctx, domain, rampwellknown.FetchOptions{
			Client: cfg.Client,
			Scheme: cfg.Scheme,
			Port:   cfg.Port,
		})
		if err != nil {
			// A failed fetch answers errors.Is the same way an empty directory
			// does. Both mean one thing to a caller: no key could be resolved for
			// this exchange, so the offer cannot be verified. Returned raw, the
			// two split — the SDK's key selector wraps the sentinel and this
			// closure did not, so the far more common case (the directory could
			// not be reached at all) arrived at the caller matching nothing and
			// was reported as unclassified. The agent-key resolver already takes
			// this stance for the same reason; see internal/agentkeys.
			//
			// The cause stays wrapped underneath, so a caller that does need to
			// tell a 404 from a dial failure still can.
			return nil, fmt.Errorf("%w: exchange %q: %w", helpers.ErrUnknownKey, domain, err)
		}
		return dir, nil
	}
	return resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{
		Fetch:   fetch,
		TTL:     cfg.TTL,
		Now:     clk.Now,
		Revoked: revoked,
	})
}

// vetDomain refuses an exchange domain that is not a plain host, before it can
// reach URL construction.
//
// It is inside the fetch closure rather than at either call site because both
// callers need it and only one of them could plausibly have checked already. A
// domain arrives here from an offer, and the whole reason it is being resolved
// is to find out whether that offer is genuine — so there is no earlier point at
// which the value has been trusted.
//
// Refused rather than trimmed to the host. Trimming would fetch a URL the caller
// did not name, on the strength of a value this package silently rewrote, and
// the answer decides whether an offer is treated as authentic. A host:port pair
// stays legal: a port is part of a host, and an exchange reachable on one says so
// in the domain its offers carry.
//
// The rule is helpers.IsBareDomain — the shape the wire admits, the same bytes
// protovalidate stamps on Offer.exchange itself. That is the right rule here
// precisely because the value arrives on the wire: this refusal and the
// Exchange's own refusal then cannot disagree about what a domain is. It is
// narrower than asking whether the value merely parses as a host.
//
// It reports the unknown-key sentinel because that is the answer to the question
// asked — no key can be resolved for this exchange — and because the one thing a
// caller does with any failure here is refuse the offer.
func vetDomain(domain string) error {
	if !helpers.IsBareDomain(domain) {
		return fmt.Errorf(
			"%w: exchange %q is not a bare domain, refusing to resolve it — a scheme, path, "+
				"query or fragment is not part of one", helpers.ErrUnknownKey, domain,
		)
	}
	return nil
}

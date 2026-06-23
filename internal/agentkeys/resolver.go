// Package agentkeys resolves an unknown agent's transport-signing key from the
// agent's own /.well-known/ramp.json, backing the Exchange httpsig middleware's
// per-agent fallback (ADR-009 D3/D4).
//
// The keyID a request signs with IS the agent's domain anchor. When a kid is
// absent from the pre-shared bootstrap key file, the middleware fetches the
// agent's published manifest (host == keyID), confirms the manifest self-asserts
// that domain, and verifies the signature against the manifest's currently-valid
// key. This is what lets a never-before-seen agent authenticate at the transport
// layer so the service can lazy-register it (service.resolveAgentLazily).
//
// The key is selected by validity window, NOT by kid: a manifest rotates kids
// freely, and the transport keyID is the identity, not the key label. The
// per-host manifest is cached (TTL) because a registered agent that is absent
// from the bootstrap file is re-resolved here on every request — caching is what
// keeps that from issuing one outbound fetch per request.
package agentkeys

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// Config wires the per-agent resolver.
type Config struct {
	// Client is the SSRF-guarded HTTP client for manifest fetches. The agent host
	// is attacker-influenced, so this MUST be guarded; nil falls back to
	// rampwellknown's guarded env client.
	Client rampwellknown.HTTPDoer
	// Scheme/Port shape the manifest URL for bare-host keyIDs on local/compose
	// stacks (RAMP_MANIFEST_FETCH_{SCHEME,PORT}); empty means https + default port.
	Scheme string
	Port   string
	// TTL bounds how long a fetched agent manifest is cached; 0 uses the
	// rampwellknown default.
	TTL time.Duration
	// Clk is the validity-window + cache-TTL time source; nil uses clock.System{}.
	Clk clock.Clock
	// Logger receives best-effort miss diagnostics; nil uses slog.Default().
	Logger *slog.Logger
}

// NewResolver returns an httpsig.KeyResolver that resolves a non-broker keyID by
// fetching the keyID's own manifest and selecting the advertised currently-valid
// key. It reports httpsig.ErrUnknownKey for a broker-prefixed kid (brokers are
// not agent domains) and for ANY fetch/parse/anchor/selection failure, so a
// CompositeResolver treats a miss as "not my key" and falls through cleanly. It
// is intended to sit LAST in the composite, after the bootstrap-file resolver.
func NewResolver(cfg Config) httpsig.KeyResolver {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clk := cfg.Clk
	if clk == nil {
		clk = clock.System{}
	}
	// Role is intentionally NOT asserted: the host == keyID anchor below is the
	// security boundary, and a caller's manifest may legitimately be AGENT or
	// PUBLISHER (mirrors agentreg.RegisterFromManifest's reasoning).
	cache := rampwellknown.NewCache(rampwellknown.CacheOptions{
		Client: cfg.Client,
		Scheme: cfg.Scheme,
		Port:   cfg.Port,
		TTL:    cfg.TTL,
		Clk:    clk,
	})
	return httpsig.ResolverFunc(func(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
		if keyID == "" || strings.HasPrefix(keyID, httpsig.BrokerKeyIDPrefix) {
			return nil, fmt.Errorf("%w: %q is not an agent domain", httpsig.ErrUnknownKey, keyID)
		}
		pub, err := resolveAgentKey(ctx, cache, clk, keyID)
		if err != nil {
			// Absent / unreachable / malformed / anchor-mismatch / all-expired all
			// mean "cannot verify against this agent's published key": report
			// unknown so the composite exhausts to ErrUnknownKey (→ 401).
			logger.DebugContext(ctx, "agent well-known key resolution miss", "keyid", keyID, "err", err)
			return nil, fmt.Errorf("%w: %q: %w", httpsig.ErrUnknownKey, keyID, err)
		}
		return pub, nil
	})
}

// resolveAgentKey fetches keyID's manifest (host == keyID, ADR-009 anchor),
// confirms the manifest self-asserts that same domain, and returns its
// currently-valid Ed25519 key. The domain == keyID check is the anti-spoofing
// boundary: a manifest served at keyID's host but claiming another domain is
// refused.
func resolveAgentKey(
	ctx context.Context, cache *rampwellknown.Cache, clk clock.Clock, keyID string,
) (ed25519.PublicKey, error) {
	m, err := cache.Get(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if m.GetDomain() != keyID {
		return nil, fmt.Errorf("manifest domain %q does not anchor keyid %q", m.GetDomain(), keyID)
	}
	return rampwellknown.ActiveKey(m, clk.Now())
}

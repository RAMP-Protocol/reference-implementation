package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// buildHTTPSigDeps constructs the RFC 9421 KeyResolver + ReplayStore used by
// the httpsig middleware. Keys are loaded from the JWKS file at
// RAMP_KEYS_FILE (default deploy/broker/keys.json) — in the v1 demo both
// Broker and Exchange read the same file, which carries agent pubkeys AND
// the Broker-relay pubkey disambiguated by kid prefix. Redis, when REDIS_URL
// is set, backs the replay store; otherwise an in-memory store is used.
func buildHTTPSigDeps(
	ctx context.Context, logger *slog.Logger, fetchClient rampwellknown.HTTPDoer,
) (httpsig.KeyResolver, httpsig.ReplayStore, error) {
	keysFile := runhttp.EnvOr("RAMP_KEYS_FILE", "deploy/broker/keys.json")
	var redisCli *redis.Client
	if dsn := runhttp.EnvOr("REDIS_URL", ""); dsn != "" {
		opts, err := redis.ParseURL(dsn)
		if err != nil {
			return nil, nil, err
		}
		redisCli = redis.NewClient(opts)
		if pingErr := redisCli.Ping(ctx).Err(); pingErr != nil {
			_ = redisCli.Close()
			return nil, nil, pingErr
		}
		logger.Info("httpsig: redis replay store ready", "addr", opts.Addr)
	}
	static, replay, err := httpsig.Wireup(httpsig.WireupOptions{
		KeysFile:    keysFile,
		Redis:       redisCli,
		RedisPrefix: "httpsig:exchange:replay:",
	})
	if err != nil {
		return nil, nil, err
	}
	return wellKnownAwareResolver(ctx, static, fetchClient, logger), replay, nil
}

// wellKnownAwareResolver wraps the static RAMP_KEYS_FILE resolver. When
// EXCHANGE_BROKER_WELLKNOWN_URL is set, a revocation-aware rampwellknown.Loader
// bound to that URL is consulted first — so a kid the Broker has revoked (or
// whose validity window has lapsed) is rejected even if the bootstrap file
// still lists it. Then the static file. Then — last — a per-agent well-known
// fallback (ADR-009 D2) that fetches an unknown agent's own manifest so a
// never-before-seen agent can authenticate at the transport layer and be
// lazy-registered by the service; disabled by EXCHANGE_AGENT_WELLKNOWN_RESOLUTION=0.
func wellKnownAwareResolver(
	ctx context.Context, static httpsig.KeyResolver, fetchClient rampwellknown.HTTPDoer, logger *slog.Logger,
) httpsig.KeyResolver {
	// Authority order: broker revocation channel (if configured) overrides the
	// bootstrap file, then the static file, then — last — the per-agent
	// well-known fallback for genuinely unknown agent kids. Static stays a
	// no-network fast path for known kids; the agent fetch only runs when every
	// earlier delegate reports the kid unknown.
	base := static
	if url := runhttp.EnvOr("EXCHANGE_BROKER_WELLKNOWN_URL", ""); url != "" {
		base = httpsig.NewCompositeResolver(brokerRevocationResolver(ctx, url, fetchClient, logger), static)
	}
	if !runhttp.EnvBool("EXCHANGE_AGENT_WELLKNOWN_RESOLUTION", true) {
		return base
	}
	agent := agentkeys.NewResolver(agentkeys.Config{
		Client: fetchClient,
		Scheme: runhttp.EnvOr("RAMP_MANIFEST_FETCH_SCHEME", ""),
		Port:   runhttp.EnvOr("RAMP_MANIFEST_FETCH_PORT", ""),
		Logger: logger,
	})
	logger.Info("httpsig: per-agent well-known key resolution enabled (ADR-009 D2)")
	return httpsig.NewCompositeResolver(base, agent)
}

// brokerRevocationResolver resolves a kid against the Broker's well-known
// manifest, treating a revoked/expired verdict as authoritative (not masked by a
// later static fallback) and any unreachable/unknown result as ErrUnknownKey so
// the composite falls through. The loader's revocation poller runs on ctx.
func brokerRevocationResolver(
	ctx context.Context, url string, fetchClient rampwellknown.HTTPDoer, logger *slog.Logger,
) httpsig.KeyResolver {
	poll := runhttp.EnvDuration("EXCHANGE_REVOCATION_POLL_INTERVAL", 0)
	loader := rampwellknown.NewLoader(rampwellknown.LoaderOptions{
		Fetch:        rampwellknown.FetchOptions{Client: fetchClient},
		PollInterval: poll,
		ManifestTTL:  runhttp.EnvDuration("EXCHANGE_MANIFEST_TTL", 0),
		Logger:       logger,
	})
	go loader.Run(ctx)
	logger.Info("httpsig: well-known revocation-aware resolution enabled",
		"well_known_url", url, "poll_interval", poll)
	return httpsig.ResolverFunc(func(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
		pub, err := loader.LookupKey(ctx, url, keyID)
		switch {
		case err == nil:
			return pub, nil
		case errors.Is(err, rampwellknown.ErrKeyRevoked), errors.Is(err, rampwellknown.ErrKeyExpired):
			return nil, err // authoritative negative — do not fall through to the file
		default:
			// Unknown here, or the document is unreachable/malformed: defer to
			// the static fallback by reporting the kid as unknown.
			return nil, fmt.Errorf("%w: %w", httpsig.ErrUnknownKey, err)
		}
	})
}

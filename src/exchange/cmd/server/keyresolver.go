package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"github.com/redis/go-redis/v9"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// buildHTTPSigDeps constructs the RFC 9421 KeyResolver + ReplayStore used by
// the connectserver verify middleware. Keys are loaded from the JWKS file at
// RAMP_KEYS_FILE (default deploy/broker/keys.json) — in the v1 demo both
// Broker and Exchange read the same file, which carries the agent and
// Broker-relay pubkeys keyed by their RFC 7638 thumbprints (the WBA split
// retired the domain/kid-prefix keyid convention). Redis, when REDIS_URL is
// set, backs the replay store; otherwise an in-memory store is used.
func buildHTTPSigDeps(
	ctx context.Context, logger *slog.Logger, fetchClient *http.Client,
) (helpers.KeyResolver, *replay.CoreAdapter, error) {
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
		logger.Info("exchange.httpsig.replay_store_ready", "addr", opts.Addr)
	} else {
		// Announce the fallback rather than leaving its absence as the only
		// evidence: a per-process replay store is correct at one instance and
		// unsafe above it, so the state has to be greppable. Matches the
		// Broker's broker.redis.disabled, level included.
		logger.Info("exchange.httpsig.replay_store_disabled")
	}
	static, replayStore, err := wireupKeyResolver(keysFile, redisCli, "httpsig:exchange:replay:")
	if err != nil {
		return nil, nil, err
	}
	resolver, err := wellKnownAwareResolver(ctx, static, fetchClient, logger)
	if err != nil {
		return nil, nil, err
	}
	return resolver, replayStore, nil
}

// wireupKeyResolver loads the static key resolver from a JWKS file and builds
// the replay store (Redis or in-memory). It is the Wireup equivalent for the
// Exchange after the httpsig package is deleted. The resolver is a
// keypolicy.TimedStaticResolver (not the SDK's window-blind StaticKeyResolver)
// so a lapsed/not-yet-valid key in the bootstrap file is rejected with
// ErrKeyExpired rather than verifying unconditionally.
func wireupKeyResolver(
	keysFile string, redisCli *redis.Client, redisPrefix string,
) (*keypolicy.TimedStaticResolver, *replay.CoreAdapter, error) {
	resolver := keypolicy.NewTimedStaticResolver(nil)
	if keysFile != "" {
		if err := loadKeysFileIntoResolver(resolver, keysFile); err != nil {
			return nil, nil, err
		}
	}
	return resolver, replay.NewCoreAdapter(replay.NewStore(redisCli, redisPrefix)), nil
}

// wellKnownAwareResolver wraps the static RAMP_KEYS_FILE resolver.
// EXCHANGE_BROKER_WELLKNOWN_URL is REQUIRED: a revocation-aware SDK
// WBAKeyResolver bound to that URL is consulted FIRST — so a kid the Broker has
// revoked (or whose validity window has lapsed) is rejected even if the
// bootstrap file still lists it. Then the static file. Then — last — a
// per-agent well-known fallback (ADR-009 D2) that fetches an unknown agent's own
// manifest so a never-before-seen agent can authenticate at the transport layer
// and be lazy-registered by the service; disabled by
// EXCHANGE_AGENT_WELLKNOWN_RESOLUTION=0.
//
// The URL is mandatory by design: without a revocation authority ahead of the
// static bootstrap file, a revoked key keeps verifying for as long as the file
// lists it. Rather than log a warning and boot fail-open, this refuses
// to boot when the URL is unset — the caller propagates the error.
func wellKnownAwareResolver(
	ctx context.Context, static helpers.KeyResolver, fetchClient *http.Client, logger *slog.Logger,
) (helpers.KeyResolver, error) {
	url := runhttp.EnvOr("EXCHANGE_BROKER_WELLKNOWN_URL", "")
	if url == "" {
		return nil, errors.New("EXCHANGE_BROKER_WELLKNOWN_URL is required: refusing to boot " +
			"without a revocation authority ahead of the static bootstrap key file " +
			"(a revoked key would otherwise keep verifying)")
	}
	// Authority order: broker revocation channel overrides the bootstrap file,
	// then the static file, then — last — the per-agent well-known fallback for
	// genuinely unknown agent kids. Static stays a no-network fast path for known
	// kids; the agent fetch only runs when every earlier delegate reports the kid
	// unknown.
	base := keypolicy.NewCompositeResolver(brokerRevocationResolver(ctx, url, fetchClient, logger), static)
	if !runhttp.EnvBool("EXCHANGE_AGENT_WELLKNOWN_RESOLUTION", true) {
		return base, nil
	}
	agent := agentkeys.NewFromEnv(ctx, fetchClient, logger)
	logger.Info("exchange.httpsig.agent_wellknown_enabled")
	return keypolicy.NewCompositeResolver(base, agent), nil
}

// brokerRevocationResolver resolves a kid against the Broker's WBA directory.
// A revoked/expired verdict is authoritative (not masked by a later static or
// per-agent fallback). A successfully-fetched directory that simply lacks the
// kid (ErrUnknownKey) reports the kid unknown so the composite falls through.
// A fetch/parse failure (ErrDirectoryUnavailable), however, FAILS CLOSED: the
// revocation channel is unavailable, so we cannot prove the kid is not revoked
// — returning a non-ErrUnknownKey error halts the composite (both the static
// file and the per-agent fallback) rather than silently re-enabling a
// possibly-revoked kid on a well-known outage. The SDK resolver's revocation
// poller runs on ctx.
//
// The Broker's directory is a FIXED config URL (EXCHANGE_BROKER_WELLKNOWN_URL),
// not a request header: the SDK resolver reads its directory from the context's
// Signature-Agent slot, so this delegate explicitly overrides that slot with
// the configured URL on every Resolve — the request's own Signature-Agent (an
// agent's directory, or absent) must never steer the BROKER revocation lookup.
//
// A thumbprint the broker revoked but which its directory never listed (e.g. a
// key carried only by the static bootstrap file) resolves to ErrUnknownKey —
// the SDK gates the revocation snapshot only for directory-listed keys, since
// removal is deliberately not revocation. This delegate closes that gap by
// consulting the SDK's revocation-set-membership accessor on that verdict:
// wba.Revoked reports snapshot membership independent of directory listing, so
// a revoked-but-directory-absent thumbprint is rejected here (fail-closed)
// instead of falling through to the static file and re-admitting a revoked key.

func brokerRevocationResolver(
	ctx context.Context, url string, fetchClient *http.Client, logger *slog.Logger,
) helpers.KeyResolver {
	poll := runhttp.EnvDuration("EXCHANGE_REVOCATION_POLL_INTERVAL", 0)
	resolver := keypolicy.RunningWBAResolver(ctx, resolvers.WBAKeyResolverOptions{
		HTTP:         fetchClient,
		PollInterval: poll,
		TTL:          runhttp.EnvDuration("EXCHANGE_DIRECTORY_TTL", 0),
		Logger:       logger,
	})
	logger.Info("exchange.httpsig.wellknown_enabled",
		"well_known_url", url, "poll_interval", poll)
	return keypolicy.ResolverFunc(func(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
		pub, err := resolver.Resolve(helpers.WithSignatureAgent(ctx, url), keyID)
		switch {
		case err == nil:
			return pub, nil
		case errors.Is(err, helpers.ErrUnknownKey):
			// The directory was fetched and parsed but carries no such kid. The
			// directory is authoritative about which kids it LISTS, but the
			// revocation channel is authoritative about which thumbprints are
			// REVOKED regardless of directory membership. A kid the broker has
			// revoked but never listed in the directory must still be rejected so a
			// static-bootstrap-only key cannot bypass the revocation guarantee this
			// resolver exists to provide: consult the SDK's revocation-set
			// membership accessor, which reports snapshot membership independent of
			// directory listing. A revoked-but-unlisted thumbprint fails closed
			// here (ErrKeyRevoked halts the composite); otherwise the kid is
			// genuinely unknown to the broker and the bootstrap file (or the
			// per-agent fallback) may legitimately carry it, so fall through.
			if resolver.Revoked(keyID) {
				return nil, fmt.Errorf("%w: directory-absent keyid=%q on broker revocation list", resolvers.ErrKeyRevoked, keyID)
			}
			return nil, err
		case errors.Is(err, resolvers.ErrKeyRevoked), errors.Is(err, resolvers.ErrKeyExpired):
			return nil, err // authoritative negative — do not fall through to the file
		default:
			// ErrDirectoryUnavailable (fetch/decode failure) and anything else:
			// the revocation channel is unavailable, so we CANNOT prove this kid
			// is not revoked. Fail closed rather than fall through to the static
			// bootstrap file or the per-agent fallback, which would silently
			// re-enable a possibly-revoked-but-static-listed kid on a well-known
			// outage. Returning a non-ErrUnknownKey error stops the
			// CompositeResolver here. The WARN is the metric signal — the outage
			// is observable, never silent.
			logger.WarnContext(ctx, "exchange.httpsig.broker_wellknown_unavailable",
				"keyid", keyID, "well_known_url", url, "err", err)
			return nil, err
		}
	})
}

// loadKeysFileIntoResolver pushes every Ed25519 key in the static bootstrap JWKS
// (RAMP_KEYS_FILE) into resolver, keyed by RFC 7638 thumbprint and carrying each
// entry's optional not_before/not_after validity window, via the shared
// fail-closed keypolicy.LoadJWKSFile loader. A statically-listed key is held to
// the same validity gate as a directory-published one; malformed entries (bad
// kty/crv, undecodable x, unparseable window) are skipped. Zero keys loaded (an
// empty or all-malformed file) is fatal here — the Exchange needs at least one
// static verify key to serve.
func loadKeysFileIntoResolver(resolver *keypolicy.TimedStaticResolver, path string) error {
	loaded := 0
	if err := keypolicy.LoadJWKSFile(path, func(tk keypolicy.TimedKey) {
		resolver.PutTimed(tk.Thumbprint, tk.Public, tk.NotBefore, tk.NotAfter)
		loaded++
	}); err != nil {
		return err
	}
	if loaded == 0 {
		return errors.New("httpsig: no keys loaded (empty or malformed JWKS)")
	}
	return nil
}

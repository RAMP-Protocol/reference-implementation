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
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
)

// buildHTTPSigDeps constructs the RFC 9421 KeyResolver + ReplayStore used by
// the connectserver verify middleware. Every verification key is learned via
// well-known discovery — there is no static key file: the Broker's WBA
// directory (EXCHANGE_BROKER_WELLKNOWN_URL, also the revocation authority)
// carries the Broker relay key, and each agent's own directory (named by the
// signed Signature-Agent header) carries that agent's keys. Redis, when
// REDIS_URL is set, backs the replay store; otherwise an in-memory store is
// used.
func buildHTTPSigDeps(
	ctx context.Context, logger *slog.Logger, fetchClient *http.Client,
) (helpers.KeyResolver, *replay.CoreAdapter, error) {
	// The fail-closed guard runs FIRST, before anything opens a connection or
	// starts a goroutine: a boot this guard is about to refuse must not dial
	// Redis, and must not start the per-agent revocation poller
	// (agentkeys.NewFromEnv starts it on ctx — the boot-guard test verifies
	// the refused boot leaks no goroutine). The URL is read exactly once,
	// here, and passed down.
	url, err := requireBrokerWellKnownURL()
	if err != nil {
		return nil, nil, err
	}
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
	replayStore := replay.NewCoreAdapter(replay.NewStore(redisCli, "httpsig:exchange:replay:"))
	agent := agentkeys.NewFromEnv(ctx, fetchClient, logger)
	return wellKnownAwareResolver(ctx, url, agent, fetchClient, logger), replayStore, nil
}

// requireBrokerWellKnownURL reads EXCHANGE_BROKER_WELLKNOWN_URL and refuses an
// empty value. The URL is mandatory by design: without a revocation authority
// ahead of the per-agent path, a key the Broker revoked would keep verifying
// for as long as some later delegate still resolves it. Rather than log a
// warning and boot fail-open, an unset URL refuses the boot — the caller
// propagates the error.
func requireBrokerWellKnownURL() (string, error) {
	url := runhttp.EnvOr("EXCHANGE_BROKER_WELLKNOWN_URL", "")
	if url == "" {
		return "", errors.New("EXCHANGE_BROKER_WELLKNOWN_URL is required: refusing to boot " +
			"without a revocation authority ahead of the per-agent well-known path " +
			"(a revoked key would otherwise keep verifying)")
	}
	return url, nil
}

// wellKnownAwareResolver composes the Exchange's verification-key chain.
// EXCHANGE_BROKER_WELLKNOWN_URL is REQUIRED: a revocation-aware SDK
// WBAKeyResolver bound to that URL is consulted FIRST — so a kid the Broker has
// revoked (or whose validity window has lapsed) is rejected authoritatively. A
// kid the Broker's directory does not carry falls through to next — in
// production the per-agent well-known resolver (ADR-009 D2), which fetches the
// unknown signer's own /.well-known/http-message-signatures-directory so a
// never-before-seen agent can authenticate at the transport layer and be
// lazy-registered by the service.
//
// url is EXCHANGE_BROKER_WELLKNOWN_URL, read and validated once by the
// caller's boot guard (requireBrokerWellKnownURL holds the rationale and the
// refusal) and bound here.
//
// What retires a rotated Broker relay key — both mechanisms, in different
// roles. Routine rotation: the Broker's next boot publishes only the new key,
// so a re-fetched directory stops resolving the old thumbprint within the
// directory cache TTL, and the published validity window (stamped as 90 days
// from the clock at each periodic document rebuild) bounds how long a stale
// cached copy can keep the old key verifying — the SDK resolver rejects a
// lapsed window as ErrKeyExpired, which is authoritative below. Compromise:
// the Broker's revocation list, consulted first by this composite, retires
// the thumbprint immediately, even while some directory still publishes it. Neither substitutes for the other:
// the window needs no operator action but takes up to its full span to bite;
// the revocation list is immediate but is an explicit operator act.
func wellKnownAwareResolver(
	ctx context.Context, url string, next helpers.KeyResolver, fetchClient *http.Client, logger *slog.Logger,
) helpers.KeyResolver {
	// Authority order: the broker revocation channel first, then the fall-through
	// delegate for genuinely unknown kids. The broker delegate's verdicts on
	// revoked/expired/unavailable are authoritative and halt the composite; only
	// a fetched-and-parsed directory that simply lacks the kid falls through.
	return keypolicy.NewCompositeResolver(brokerRevocationResolver(ctx, url, fetchClient, logger), next)
}

// brokerRevocationResolver resolves a kid against the Broker's WBA directory.
// A revoked/expired verdict is authoritative (not masked by a later delegate).
// A successfully-fetched directory that simply lacks the kid (ErrUnknownKey)
// reports the kid unknown so the composite falls through. A fetch/parse failure
// (ErrDirectoryUnavailable), however, FAILS CLOSED: the revocation channel is
// unavailable, so we cannot prove the kid is not revoked — returning a
// non-ErrUnknownKey error halts the composite (the per-agent fallback included)
// rather than silently re-enabling a possibly-revoked kid on a well-known
// outage. The SDK resolver's revocation poller runs on ctx.
//
// The Broker's directory is a FIXED config URL (EXCHANGE_BROKER_WELLKNOWN_URL),
// not a request header: the SDK resolver reads its directory from the context's
// Signature-Agent slot, so this delegate explicitly overrides that slot with
// the configured URL on every Resolve — the request's own Signature-Agent (an
// agent's directory, or absent) must never steer the BROKER revocation lookup.
//
// A thumbprint the broker revoked but which its directory never listed (e.g. a
// key some other party's directory still publishes) resolves to ErrUnknownKey —
// the SDK gates the revocation snapshot only for directory-listed keys, since
// removal is deliberately not revocation. This delegate closes that gap by
// consulting the SDK's revocation-set-membership accessor on that verdict:
// wba.Revoked reports snapshot membership independent of directory listing, so
// a revoked-but-directory-absent thumbprint is rejected here (fail-closed)
// instead of falling through to the per-agent fallback and re-admitting a
// revoked key.

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
			// key resolvable only through a later delegate cannot bypass the
			// revocation guarantee this resolver exists to provide: consult the
			// SDK's revocation-set membership accessor, which reports snapshot
			// membership independent of directory listing. A revoked-but-unlisted
			// thumbprint fails closed here (ErrKeyRevoked halts the composite);
			// otherwise the kid is genuinely unknown to the broker and the
			// per-agent fallback may legitimately carry it, so fall through.
			if resolver.Revoked(keyID) {
				return nil, fmt.Errorf("%w: directory-absent keyid=%q on broker revocation list", resolvers.ErrKeyRevoked, keyID)
			}
			return nil, err
		case errors.Is(err, resolvers.ErrKeyRevoked), errors.Is(err, resolvers.ErrKeyExpired):
			return nil, err // authoritative negative — do not fall through
		default:
			// ErrDirectoryUnavailable (fetch/decode failure) and anything else:
			// the revocation channel is unavailable, so we CANNOT prove this kid
			// is not revoked. Fail closed rather than fall through to the
			// per-agent fallback, which would silently re-enable a
			// possibly-revoked kid on a well-known outage. Returning a
			// non-ErrUnknownKey error stops the CompositeResolver here. The WARN
			// is the metric signal — the outage is observable, never silent.
			logger.WarnContext(ctx, "exchange.httpsig.broker_wellknown_unavailable",
				"keyid", keyID, "well_known_url", url, "err", err)
			return nil, err
		}
	})
}

// admissionDeps are the checks a request clears before a handler sees it: who
// signed it, whether that signature has been seen before, how many hops it may
// carry, and whether it names this Exchange at all. They travel together
// because they are one decision — admit this request or refuse it — and because
// building them in one place keeps run() linear.
type admissionDeps struct {
	resolver      helpers.KeyResolver
	replay        *replay.CoreAdapter
	maxSignatures int
	audience      *rampaudience.Interceptor
}

// buildAdmissionDeps wires them from the environment.
//
// The recipient interceptor is built HERE, at boot, rather than per request: a
// misconfigured EXCHANGE_DOMAIN then stops the process, instead of refusing
// honest callers with an internal error that names nothing an operator can act
// on.
func buildAdmissionDeps(
	ctx context.Context, logger *slog.Logger, fetchClient *http.Client,
) (admissionDeps, error) {
	resolver, replayAdapter, err := buildHTTPSigDeps(ctx, logger, fetchClient)
	if err != nil {
		return admissionDeps{}, err
	}
	audience, err := rampaudience.NewInterceptor(exchangeDomain())
	if err != nil {
		return admissionDeps{}, err
	}
	return admissionDeps{
		resolver:      resolver,
		replay:        replayAdapter,
		maxSignatures: int(exchangeMaxIntermediaryHops()) + 1,
		audience:      audience,
	}, nil
}

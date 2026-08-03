// Broker wiring builders: the well-known endpoint resolver, the offer
// Verifier, and the registry repositories run() composes. Split from main.go
// to keep both files under the file-length cap.
package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/offerkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/probe"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// newDiscoveryEndpointResolver builds the SINGLE well-known endpoint resolver
// the discovery and execute-relay paths share (wired once into
// resolveDeps.Endpoints and consumed by both): each routed exchange's endpoint
// is resolved from the exchange's OWN /.well-known/ramp.json (the registry is a
// trust allowlist only; no backfilled registry endpoint is ever queried).
// Scheme is deploy-aware (https prod, http e2e) via RAMP_WELLKNOWN_SCHEME.
// The fetch client is the env-guarded SSRF client: the GetByDomain /
// endpointAllowed registry checks only bound the host STRING, so the guard's
// dial-time public-IP enforcement is what refuses a registered domain that
// rebinds to a private/metadata address. This matches the broker's other
// well-known fetches (guardedFetch for the prober + agent resolver), so the
// SSRF default lives once. The guard is SDK-owned; the client is constructed from
// resolvers.NewGuardedClientFromEnv (best-effort address + scheme guards, driven
// by SKIP_SSRF / ALLOW_INSECURE).
func newDiscoveryEndpointResolver() *resolvers.WellKnownEndpointResolver {
	return resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
		HTTP:   resolvers.NewGuardedClientFromEnv(),
		Scheme: runhttp.EnvOr("RAMP_WELLKNOWN_SCHEME", "https"),
	})
}

// newOfferVerifier builds the fail-closed offer Verifier the resolve core sorts
// every discovered offer through (the broker no longer relays
// unverified offers on the typed path). Keys resolve per exchange DOMAIN from
// the exchange's OWN WBA directory (the offer-signing key's only home after the
// WBA split), over the same guarded fetch + deploy-aware scheme the endpoint
// resolver uses. The clock is injected (never time.Now inline) so the
// Verifier's expiry decisions are deterministic under test, matching every
// other broker wiring site.
func newOfferVerifier(clk clock.Clock) core.Verifier {
	resolver := offerkeys.New(offerkeys.Config{
		Client: resolvers.NewGuardedClientFromEnv(),
		Scheme: runhttp.EnvOr("RAMP_WELLKNOWN_SCHEME", "https"),
		Clk:    clk,
	})
	return core.NewVerifier(core.Strict, resolver, clk.Now)
}

// brokerFetchWiring bundles the outbound-fetch-dependent broker collaborators
// built at the composition root: the publisher probe and per-agent WBA key
// resolver (over one shared SDK-guarded client), the shared well-known endpoint
// resolver, and the fail-closed offer Verifier. Each fetch client is constructed
// from the SDK factory resolvers.NewGuardedClientFromEnv (best-effort address +
// scheme guards, driven by SKIP_SSRF / ALLOW_INSECURE).
type brokerFetchWiring struct {
	prober        *probe.Prober
	agentResolver helpers.KeyResolver
	endpoints     *resolvers.WellKnownEndpointResolver
	verifier      core.Verifier
}

// buildFetchWiring builds the probe/agent-resolver pair and the resolve-path
// endpoint resolver + offer Verifier.
func buildFetchWiring(ctx context.Context, logger *slog.Logger) brokerFetchWiring {
	prober, agentResolver := buildProbeWiring(ctx, logger)
	return brokerFetchWiring{
		prober:        prober,
		agentResolver: agentResolver,
		endpoints:     newDiscoveryEndpointResolver(),
		verifier:      newOfferVerifier(clock.System{}),
	}
}

// setupRegistryRepos builds the exchange/selection-log repositories and seeds
// the exchange trust registry from the bootstrap env.
func setupRegistryRepos(
	ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger,
) (*repo.PgxExchangeRepo, *repo.PgxSelectionLogRepo, error) {
	exchangeRepo := repo.NewExchangeRepo(pool)
	logRepo := repo.NewSelectionLogRepo(pool)
	if err := bootstrapRegistry(ctx, exchangeRepo, logger); err != nil {
		return nil, nil, fmt.Errorf("registry bootstrap: %w", err)
	}
	return exchangeRepo, logRepo, nil
}

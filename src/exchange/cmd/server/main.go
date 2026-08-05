// Package main is the Exchange service entrypoint.
//
// The Exchange implements ramp.v1.ExchangeService and ramp.v1.CatalogService:
// catalog lookup, Ed25519 offer signing, transaction execution with a
// write-before-sign invariant, signed URL minting (Ed25519 or RSA CloudFront
// per tenant), and usage reporting.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	connectrpc "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/wellknown"
)

func main() {
	// `exchange healthcheck` probes the local /healthz and exits — the
	// distroless image has no shell or curl, so the compose healthcheck
	// execs the service binary itself.
	runhttp.MaybeHealthcheck("EXCHANGE_ADDR", ":8081")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	// Tie the lifecycle context to the process shutdown signals so background
	// goroutines started on it (the per-agent WBA revocation poller) stop on
	// shutdown instead of leaking. runhttp.ServeGroup installs its own signal
	// handler for HTTP drain; both registrations receive the signal. stop() is
	// called explicitly (not deferred) so it runs before a non-zero os.Exit.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, logger)
	stop()
	if err != nil {
		logger.Error("exchange.exit", "err", err)
		os.Exit(1)
	}
}

// run is main() minus the os.Exit call; splitting it this way lets defers fire
// cleanly regardless of which stage fails.
func run(ctx context.Context, logger *slog.Logger) error {
	pool, err := db.Setup(ctx, db.SetupOptions{
		DSN:             runhttp.EnvOr("EXCHANGE_DSN", ""),
		Migrations:      exchangedb.Migrations,
		MigrationsDir:   exchangedb.MigrationsDir,
		MigrationsTable: exchangedb.MigrationsTable,
	}, logger)
	if err != nil {
		return fmt.Errorf("db setup: %w", err)
	}
	if pool == nil {
		return errors.New("EXCHANGE_DSN is required")
	}
	defer pool.Close()

	keys, err := setupDemoKeys(logger)
	if err != nil {
		return err
	}
	offerSigner, keystore := keys.offerSigner, keys.keystore

	// One SSRF-guarded HTTP client backs every outbound .well-known fetch:
	// agent registration, catalog contributor-authz, and the broker revocation
	// poll. The guard is SDK-owned; construct it once here at the composition root
	// and inject it into every fetch site. It refuses loopback/link-local/private
	// destinations unless SKIP_SSRF is set, and refuses plaintext http unless
	// ALLOW_INSECURE is set (compose/dev only).
	fetchClient := resolvers.NewGuardedClientFromEnv()

	queries := sqlc.New(pool)
	// Surface a missing default tenant at boot rather than only on the first
	// Register. This warns and continues — a deployment may seed tenants after the
	// process starts (see warnIfDefaultTenantMissing).
	warnIfDefaultTenantMissing(ctx, logger, repo.NewTenantReadRepo(queries))
	// Gate-1 self-signup fetches a caller's own /.well-known/ramp.json to learn
	// its signing key. It honors the SAME RAMP_WELLKNOWN_{SCHEME,PORT} the
	// Gate-2 publisher-manifest cache uses (newManifestCache), so a compose/local
	// http edge is reachable without a DB key pre-seed.
	agentRegistry := agentreg.New(agentreg.Config{
		Repo:   repo.NewAgentRepo(queries),
		HTTP:   fetchClient,
		Scheme: runhttp.EnvOr("RAMP_WELLKNOWN_SCHEME", "https"),
		Port:   runhttp.EnvOr("RAMP_WELLKNOWN_PORT", ""),
	})
	// EXCHANGE_CATALOG_URI_SCHEME defaults to https; compose overrides to http
	// so catalog URIs route through the in-network edge worker.
	service.SetCatalogURIScheme(runhttp.EnvOr("EXCHANGE_CATALOG_URI_SCHEME", ""))
	catalogSvc := service.NewCatalogService(
		repo.NewCatalogRepo(queries), repo.NewTenantReadRepo(queries),
		agentRegistry, newManifestCache(fetchClient), db.PoolRunner{Pool: pool},
		runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local"),
	)
	// Pre-render CoMP for the advertised profiles at rebuild. Same
	// single source as the manifest + ExchangeConfig; set BEFORE Bootstrap so the
	// first rebuild renders.
	catalogSvc.SetSupportedProfiles(exchangeSupportedProfiles())
	if err := catalogSvc.Bootstrap(ctx); err != nil {
		return err
	}
	billingAdapter, sorAdapter, adaptersCleanup, err := selectAdapters(ctx, logger)
	if err != nil {
		return err
	}
	defer adaptersCleanup()
	ledgerHealth := ledgerHealthCheck(billingAdapter)
	exchangeSvc := buildExchange(buildSvcDeps{
		pool:          pool,
		queries:       queries,
		catalog:       catalogSvc,
		offerSigner:   offerSigner,
		keystore:      keystore,
		billing:       billingAdapter,
		agentRegistry: agentRegistry,
		sor:           sorAdapter,
	})
	resolver, replayAdapter, err := buildHTTPSigDeps(ctx, logger, fetchClient)
	if err != nil {
		return err
	}
	maxSignatures := int(exchangeMaxIntermediaryHops()) + 1
	mux, wk, err := buildMux(muxDeps{
		pool:          pool,
		exchange:      exchangeSvc,
		catalog:       catalogSvc,
		agentRegistry: agentRegistry,
		offerSigner:   offerSigner,
		resolver:      resolver,
		replay:        replayAdapter,
		maxSignatures: maxSignatures,
		ledgerHealth:  ledgerHealth,
	})
	if err != nil {
		return err
	}
	// The served discovery documents embed validity windows read from the
	// clock at build time, so a long-lived process must rebuild them
	// periodically or it eventually serves only lapsed windows.
	go wk.RunRefresher(ctx, wellknown.RebuildInterval, logger)

	wrapped := buildWrapped(logger, mux)
	return serveExchangeAndAdmin(ctx, logger, pool, queries, wrapped)
}

// buildSvcDeps groups the inputs buildExchange needs so the
// run() call site stays under the funlen cap.
type buildSvcDeps struct {
	pool          *pgxpool.Pool
	queries       *sqlc.Queries
	catalog       *service.CatalogService
	offerSigner   *signing.Ed25519Signer
	keystore      *signing.InMemoryKeyStore
	billing       billing.Adapter
	agentRegistry agentreg.Registry
	sor           sor.Adapter
}

// buildExchange wires the ExchangeService that serves the canonical
// DiscoverResources / ExecuteTransaction / ReportUsage RPCs. The deprecated
// OffersService (ListOffers / AcceptOffer / Report) was removed in
// W3 of the proto-rename wave.
func buildExchange(d buildSvcDeps) *service.ExchangeService {
	return service.NewExchangeService(service.ExchangeDeps{
		TxRunner:      db.PoolRunner{Pool: d.pool},
		Catalog:       d.catalog,
		Tenants:       repo.NewTenantReadRepo(d.queries),
		Agents:        repo.NewAgentRepo(d.queries),
		AgentReg:      d.agentRegistry,
		Transactions:  repo.NewTransactionRepo(d.queries),
		Obligations:   repo.NewObligationRepo(d.queries),
		Evidence:      repo.NewEvidenceRepo(d.queries),
		FeeOverrides:  repo.NewFeeOverrideRepo(d.queries),
		Billing:       d.billing,
		OfferSigner:   d.offerSigner,
		KeyStore:      d.keystore,
		SoR:           d.sor,
		BillingRefGen: uuid.NewString,
		Clk:           clock.System{},
		Config: service.ExchangeConfig{
			Exchange:          runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local"),
			SupportedProfiles: exchangeSupportedProfiles(),
			// The single default tenant a Register reads its
			// activate_new_agents_by_default policy from (ADR-021 §5 decision 1).
			DefaultTenantDomain: defaultTenantDomain(),
		},
	})
}

// buildWrapped assembles the Exchange's outermost HTTP middleware: the shared
// public-surface stack around CatalogSignatureMiddleware → mux (see
// transport.WrapPublicSurface), with the deployment-shape switches read from
// the environment here at the composition root (see
// runhttp.PublicSurfaceOptionsFromEnv for the fail-closed opt-in rationale).
// ExchangeService and CatalogService RPC verification is delegated to
// connectserver handlers (registered in registerConnect), which each carry
// their own request-id + RFC 9421 verify layers.
func buildWrapped(logger *slog.Logger, mux http.Handler) http.Handler {
	return transport.WrapPublicSurface(logger, mux, runhttp.PublicSurfaceOptionsFromEnv())
}

// muxDeps collects everything buildMux needs so run() can stay linear and
// tests can assemble the Exchange's HTTP surface without booting real services.
type muxDeps struct {
	pool          interface{ Ping(context.Context) error }
	exchange      *service.ExchangeService
	catalog       *service.CatalogService
	agentRegistry agentreg.Registry
	offerSigner   *signing.Ed25519Signer
	// RFC 9421 verify deps injected into connectserver.NewExchangeServiceHandler
	// (ExchangeService) and connectserver.NewCatalogServiceHandler (CatalogService).
	// CatalogService also runs its own per-contributor check in
	// CatalogHandler.verifyCallerSignature; this resolver backs the connectserver
	// standard verify layer.
	resolver      helpers.KeyResolver
	replay        *replay.CoreAdapter
	maxSignatures int
	// ledgerHealth probes the billing ledger for /readyz. Nil when the selected
	// billing backend has no ledger (free, in-memory), which is the common case.
	ledgerHealth func(context.Context) error
}

// buildMux wires the Exchange's HTTP surface: healthz, Connect-Go RPCs, the
// well-known endpoints, and the public agents/register route. Admin-plane
// endpoints have been removed; any request to
// /admin/* falls through to http.ServeMux's 404. The well-known handler pair
// is returned alongside the mux so run() can start its periodic refresher.
func buildMux(d muxDeps) (*http.ServeMux, server.Handlers, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthzHandler(d.pool))
	mux.HandleFunc("GET /readyz", readyzHandler(d.pool, d.ledgerHealth))
	if err := registerConnect(
		mux, d.exchange, d.catalog, d.agentRegistry, d.resolver, d.replay, d.maxSignatures,
	); err != nil {
		return nil, server.Handlers{}, err
	}
	wk, err := registerWellKnown(mux, d.offerSigner)
	if err != nil {
		return nil, server.Handlers{}, err
	}
	transport.NewAgentsRegisterHandler(d.agentRegistry, transport.AgentsRegisterOptions{}).
		RegisterRoutes(mux)
	return mux, wk, nil
}

func registerConnect(
	mux *http.ServeMux,
	m *service.ExchangeService,
	c *service.CatalogService,
	reg agentreg.Registry,
	resolver helpers.KeyResolver,
	replayAdapter *replay.CoreAdapter,
	maxSigs int,
) error {
	// connectserver.NewExchangeServiceHandler wraps the generated handler with
	// request-id (outermost) → RFC 9421 verify middleware → connect interceptors
	// (protovalidate bidirectional, via WithValidation). KeyResolver and
	// ReplayStore are injected by the application; the SDK orchestrates the
	// verify pass and replay dedup.
	svrOpts := []connectserver.ServerOption{
		connectserver.WithKeyResolver(resolver),
		connectserver.WithReplayStore(replayAdapter),
		connectserver.WithMaxSignatures(maxSigs),
		connectserver.WithValidation(connect.ValidationStrict),
		connectserver.WithEmitUnpopulated(),
		// Audit-log every gate rejection with its SDK-classified outcome
		// (replay / broken_chain / hop_budget / signature).
		connectserver.WithOnReject(transport.LogHTTPSigReject),
		// Cap the request body every Connect handler will read. A signed caller
		// must not be able to stream an unbounded body into the service; the
		// Register RPC adds a tighter, semantic bound on registration_data on
		// top. The SDK does not model a read cap, so it rides in as a raw
		// handler option.
		connectserver.WithHandlerOptions(connectrpc.WithReadMaxBytes(transport.MaxRPCReadBytes)),
	}
	path, h := connectserver.NewExchangeServiceHandler(transport.NewExchangeHandler(m), svrOpts...)
	mux.Handle(path, h)
	// CatalogService keeps the raw generated mount (its per-contributor RFC 9421
	// verification runs in CatalogSignatureMiddleware, not the SDK seam) but shares
	// the ExchangeService codec + protovalidate contract through the same raw-mount
	// options (transport.RawValidatedMountOptions — the SAME shared validation
	// engine, helpers.SharedValidator, that the ExchangeService path composes
	// through connectserver.WithValidation, so the mounts cannot drift onto forked
	// rulesets). A construction failure is a boot-time config fault: surfaced up
	// the boot chain (run() → main()) so the process exits non-zero, not a panic.
	catalogOpts, err := transport.RawValidatedMountOptions()
	if err != nil {
		return fmt.Errorf("catalog mount options: %w", err)
	}
	// The catalog mount carries the same request-body cap as the ExchangeService
	// path: the push endpoint accepts contributor-supplied payloads, so an
	// unbounded body is exactly the exposure the cap exists to close.
	catalogOpts = append(catalogOpts, connectrpc.WithReadMaxBytes(transport.MaxRPCReadBytes))
	cpath, ch := rampconnect.NewCatalogServiceHandler(transport.NewCatalogHandler(c, reg), catalogOpts...)
	mux.Handle(cpath, ch)
	return nil
}

// exchangeSupportedProfiles is the single source of truth for the extension
// profiles the Exchange advertises (WellKnownManifest.supported_profiles) AND
// projects/reconstructs on the discovery+tx paths (service.ExchangeConfig).
// ramp-comp-v1 renders the CoMP projection; ramp-news-v1 predates it.
func exchangeSupportedProfiles() []string {
	return []string{"ramp-news-v1", "ramp-comp-v1"}
}

func registerWellKnown(mux *http.ServeMux, signer *signing.Ed25519Signer) (server.Handlers, error) {
	hops := exchangeMaxIntermediaryHops()
	// Endpoint is the ExchangeService ORIGIN (e.g. http://exchange:8081), NOT a
	// service path: the manifest's top-level endpoint (WellKnownManifest.endpoint)
	// is what a broker's well-known resolver reads to route a re-packaged execute,
	// and Connect appends "/ramp.v1.ExchangeService/<Method>" to that origin
	// itself. A service-path value would double the path. Sourced from
	// EXCHANGE_PUBLIC_ORIGIN (default https://<EXCHANGE_DOMAIN>); CatalogEndpoint
	// likewise rides the origin.
	domain := runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local")
	origin := runhttp.EnvOr("EXCHANGE_PUBLIC_ORIGIN", "https://"+domain)
	wk, err := wellknown.New(wellknown.Config{
		Domain:              domain,
		Endpoint:            origin,
		CatalogEndpoint:     origin,
		BaseCurrency:        "USD",
		SupportedProfiles:   exchangeSupportedProfiles(),
		MaxIntermediaryHops: &hops,
		OfferKey:            signer.PublicKey(),
		Clock:               clock.System{},
		KeyLifetime:         wellknown.OfferKeyLifetime,
	})
	if err != nil {
		return server.Handlers{}, fmt.Errorf("register well-known: %w", err)
	}
	wk.RegisterRoutes(mux)
	return wk, nil
}

// exchangeMaxIntermediaryHops reads EXCHANGE_MAX_INTERMEDIARY_HOPS (default 4):
// the chain-depth tolerance the Exchange publishes so Brokers can prune before
// forwarding (RAMP WellKnownManifest.max_intermediary_hops). Vacuous at the
// current single-hop depth; declared so multi-hop deployments inherit a bound.
func exchangeMaxIntermediaryHops() int32 {
	const def int32 = 4
	raw := runhttp.EnvOr("EXCHANGE_MAX_INTERMEDIARY_HOPS", "")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 1<<20 {
		return def
	}
	return int32(n) //nolint:gosec // bounded to [0, 2^20] above
}

func healthzHandler(pool interface{ Ping(context.Context) error }) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if pool != nil {
			if err := pool.Ping(r.Context()); err != nil {
				http.Error(w, "db unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

// ledgerHealthCheck returns the billing backend's liveness probe, or nil when the
// selected backend has no ledger to probe.
//
// The assertion lives here, at the composition root, rather than as a method on
// billing.Adapter: only one of the three backends has a remote dependency, so putting
// Health on the shared interface would oblige the other two to answer a question they
// cannot meaningfully be asked (Architecture Rule 3 — narrow interfaces at the ports).
func ledgerHealthCheck(adapter billing.Adapter) func(context.Context) error {
	probe, ok := adapter.(interface{ Health(context.Context) error })
	if !ok {
		return nil
	}
	return probe.Health
}

// readinessProbeTimeout bounds the ledger round-trip /readyz makes. The TigerBeetle
// client's own op-timeout is 5s, which is longer than a probe should ever block —
// and long enough to time out a caller polling with `curl -m 5`. A readiness check
// that cannot answer promptly is a failed readiness check, so this cuts it short.
const readinessProbeTimeout = 2 * time.Second

// readyzHandler reports whether the Exchange can actually serve, as opposed to
// merely running. It checks the catalog database and — when the deployment runs a
// ledger — that the ledger answers.
//
// This is deliberately separate from /healthz, which stays a liveness signal over
// the database alone. The split is what
// lets an orchestrator drain an instance whose ledger has gone away WITHOUT a routine
// ledger restart also restarting the Exchange, and it keeps free resources served
// throughout: a ledger outage denies paid transactions, it does not break the process.
//
// Both checks are nil-tolerant, matching healthzHandler: a nil ledger func is the
// free/in-memory billing backend, which has no ledger to probe and is ready as soon
// as the database answers.
func readyzHandler(
	pool interface{ Ping(context.Context) error },
	ledger func(context.Context) error,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if pool != nil {
			if err := pool.Ping(r.Context()); err != nil {
				http.Error(w, "db unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if ledger != nil {
			ctx, cancel := context.WithTimeout(r.Context(), readinessProbeTimeout)
			defer cancel()
			if err := ledger(ctx); err != nil {
				http.Error(w, "ledger unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

// newManifestCache builds the publisher-manifest cache over the shared
// SSRF-guarded fetch client. Honors RAMP_WELLKNOWN_{SCHEME,PORT} for
// docker-compose / local-dev stacks; production leaves both unset (defaults to
// https + scheme-default port). ExpectRole pins every fetched manifest to
// ROLE_PUBLISHER so a misrouted document (e.g. an agent or exchange manifest)
// is rejected at the cache.
func newManifestCache(client rampwellknown.HTTPDoer) *rampwellknown.Cache {
	return rampwellknown.NewCache(rampwellknown.CacheOptions{
		Client:     client,
		Scheme:     runhttp.EnvOr("RAMP_WELLKNOWN_SCHEME", "https"),
		Port:       runhttp.EnvOr("RAMP_WELLKNOWN_PORT", ""),
		ExpectRole: rampwellknown.RolePublisher,
	})
}

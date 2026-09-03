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

	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
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
	// First, before anything connects. It reads only the environment, and a
	// schema this Exchange could not enforce stops the boot, so resolving it
	// here spends a typo's cost on one parse rather than on a database
	// connection, a migration run, a catalog bootstrap and a ledger
	// health-check per restart of the crash loop it causes. The single value
	// stays in scope for both construction sites below, so wiring the Register
	// gate later never needs a second read.
	registration, err := loadRegistrationConfig(logger)
	if err != nil {
		return err
	}
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
	if err := bootTenantConfig(ctx, logger, pool, queries); err != nil {
		return err
	}
	// Gate-1 self-signup fetches a caller's own Web Bot Auth key directory to
	// learn its signing key. It honors the SAME RAMP_WELLKNOWN_{SCHEME,PORT} the
	// Gate-2 publisher-manifest cache uses (newManifestCache), so a compose/local
	// http edge is reachable without a DB key pre-seed. The two gates read
	// different documents on the same host: keys come from the directory, and the
	// publisher's commercial overlay carries none.
	agentRegistry := agentreg.New(agentreg.Config{
		Repo:   repo.NewAgentRepo(queries),
		HTTP:   fetchClient,
		Scheme: runhttp.EnvOr("RAMP_WELLKNOWN_SCHEME", "https"),
		Port:   runhttp.EnvOr("RAMP_WELLKNOWN_PORT", ""),
	})
	catalogSvc, err := buildCatalog(ctx, pool, queries, agentRegistry, fetchClient)
	if err != nil {
		return err
	}
	billingAdapter, ledgerCurrency, sorAdapter, adaptersCleanup, err := selectAdapters(ctx, logger)
	if err != nil {
		return err
	}
	defer adaptersCleanup()
	exchangeSvc := buildExchange(buildSvcDeps{
		pool: pool, queries: queries, catalog: catalogSvc,
		offerSigner:    offerSigner,
		keystore:       keystore,
		billing:        billingAdapter,
		ledgerCurrency: ledgerCurrency,
		agentRegistry:  agentRegistry,
		sor:            sorAdapter,
		registration:   registration,
	})
	admission, err := buildAdmissionDeps(ctx, logger, fetchClient)
	if err != nil {
		return err
	}
	mux, wk, err := buildMux(muxDeps{
		pool:           pool,
		exchange:       exchangeSvc,
		catalog:        catalogSvc,
		agentRegistry:  agentRegistry,
		offerSigner:    offerSigner,
		resolver:       admission.resolver,
		replay:         admission.replay,
		audience:       admission.audience,
		ledgerHealth:   ledgerHealthCheck(billingAdapter),
		maxSignatures:  admission.maxSignatures,
		registration:   registration,
		ledgerCurrency: ledgerCurrency,
	})
	if err != nil {
		return err
	}
	// The served discovery documents embed validity windows read from the
	// clock at build time, so a long-lived process must rebuild them
	// periodically or it eventually serves only lapsed windows.
	go wk.RunRefresher(ctx, wellknown.RebuildInterval, logger)

	wrapped := buildWrapped(logger, mux)
	return serveExchangeAndAdmin(ctx, logger, pool, queries, wrapped, admission.audience)
}

// buildCatalog wires the catalog service and brings its discovery trie up from
// the database, so run() carries one call rather than the whole sequence.
func buildCatalog(
	ctx context.Context,
	pool *pgxpool.Pool,
	queries *sqlc.Queries,
	agentRegistry agentreg.Registry,
	fetchClient rampwellknown.HTTPDoer,
) (*service.CatalogService, error) {
	// EXCHANGE_CATALOG_URI_SCHEME defaults to https; compose overrides to http
	// so catalog URIs route through the in-network edge worker.
	service.SetCatalogURIScheme(runhttp.EnvOr("EXCHANGE_CATALOG_URI_SCHEME", ""))
	svc := service.NewCatalogService(
		repo.NewCatalogRepo(queries), repo.NewTenantReadRepo(queries),
		agentRegistry, newManifestCache(fetchClient), db.PoolRunner{Pool: pool},
		exchangeDomain(),
	)
	// Pre-render CoMP for the advertised profiles at rebuild. Same
	// single source as the manifest + ExchangeConfig; set BEFORE Bootstrap so the
	// first rebuild renders.
	svc.SetSupportedProfiles(exchangeSupportedProfiles())
	if err := svc.Bootstrap(ctx); err != nil {
		return nil, err
	}
	return svc, nil
}

// buildSvcDeps groups the inputs buildExchange needs so the
// run() call site stays under the funlen cap.
type buildSvcDeps struct {
	pool        *pgxpool.Pool
	queries     *sqlc.Queries
	catalog     *service.CatalogService
	offerSigner *signing.Ed25519Signer
	keystore    *signing.InMemoryKeyStore
	billing     billing.Adapter
	// ledgerCurrency is the selected billing backend's ledger currency,
	// threaded into ExchangeConfig.LedgerCurrency so the welcome-credit grant
	// and the adapter agree on the denomination.
	ledgerCurrency string
	agentRegistry  agentreg.Registry
	sor            sor.Adapter
	// registration is the operator's registration settings, read once by
	// loadRegistrationConfig. buildExchange threads its terms digest into
	// ExchangeConfig so the Register gate holds callers to exactly the digest the
	// manifest publishes, rather than reading the environment a second time.
	registration registrationConfig
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
		RegSchema:     d.registration.schema,
		Audit:         repo.NewAuditRepo(d.queries),
		BillingRefGen: uuid.NewString,
		Clk:           clock.System{},
		Config: service.ExchangeConfig{
			Exchange:          exchangeDomain(),
			SupportedProfiles: exchangeSupportedProfiles(),
			// The single default tenant a Register reads its
			// activate_new_agents_by_default policy from (ADR-021 §5 decision 1).
			DefaultTenantDomain: defaultTenantDomain(),
			LedgerCurrency:      d.ledgerCurrency,
			TermsDigest:         d.registration.termsDigest,
		},
	})
}

// exchangeDomain is this Exchange's published IDENTITY: the domain it stamps
// into the offers it issues, serves its manifest under, and answers to as the
// recipient of an addressed request.
//
// One function rather than the same EnvOr call repeated at each reader. The four
// readers — the catalog service, the offer-issuing config, the served manifest,
// and the recipient check — must agree on one value: an Exchange that issues
// offers naming one domain while refusing requests that name it is broken in a
// way each site looks correct on its own.
//
// It is NOT the host the process listens on. An Exchange at exchange.example may
// serve its API from api.exchange.example, and a deployment that put the
// listening host here would refuse every request that addressed it correctly.
func exchangeDomain() string {
	return runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local")
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
	// RFC 9421 verify deps for the ExchangeService mount, and for that mount
	// alone: they are injected into connectserver.NewExchangeServiceHandler,
	// whose verify seam resolves a caller by signature keyid.
	//
	// CatalogService reaches none of them. It mounts on the raw generated
	// handler (registerConnect below says why) and verifies its caller in
	// CatalogHandler.verifyCallerSignature, against a key resolved by caller_id
	// out of the agent registry rather than by keyid — after the Web Bot Auth
	// split the keyid is a thumbprint, which the agents table is not keyed on.
	resolver      helpers.KeyResolver
	replay        *replay.CoreAdapter
	maxSignatures int
	// ledgerCurrency is the selected billing backend's ledger currency, the
	// denomination every offer this Exchange signs is priced in. The well-known
	// document publishes it as base_currency. Never empty: the demo tiers return
	// their own constant and the TigerBeetle path refuses to boot on an unset or
	// unsupported EXCHANGE_BILLING_LEDGER.
	ledgerCurrency string
	// audience refuses a request addressed to a different Exchange. It is built
	// from EXCHANGE_DOMAIN — the identity this Exchange publishes and stamps into
	// its offers — and mounted on BOTH Connect surfaces, because an addressed
	// request reaches the catalog mount too.
	audience *rampaudience.Interceptor
	// ledgerHealth probes the billing ledger for /readyz. Nil when the selected
	// billing backend has no ledger (free, in-memory), which is the common case.
	ledgerHealth func(context.Context) error
	// registration carries the operator's registration schema and terms
	// versioning, read once so the manifest publishes exactly what the Register
	// gate will hold a caller to.
	registration registrationConfig
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
	if err := registerConnect(mux, d); err != nil {
		return nil, server.Handlers{}, err
	}
	wk, err := registerWellKnown(mux, d)
	if err != nil {
		return nil, server.Handlers{}, err
	}
	transport.NewAgentsRegisterHandler(d.agentRegistry, transport.AgentsRegisterOptions{}).
		RegisterRoutes(mux)
	return mux, wk, nil
}

func registerConnect(mux *http.ServeMux, d muxDeps) error {
	// connectserver.NewExchangeServiceHandler wraps the generated handler with
	// request-id (outermost) → RFC 9421 verify middleware → connect interceptors
	// (protovalidate bidirectional, via WithValidation). KeyResolver and
	// ReplayStore are injected by the application; the SDK orchestrates the
	// verify pass and replay dedup.
	//
	// The option set comes from the function the integration harness also calls,
	// so the mount those tests drive is this mount rather than a hand-kept copy
	// of it. A construction failure is a boot-time config fault: surfaced up the
	// boot chain (run() → main()) so the process exits non-zero, not a panic.
	svrOpts, err := transport.ExchangeMountOptions(d.resolver, d.replay, d.maxSignatures, d.audience)
	if err != nil {
		return fmt.Errorf("exchange mount options: %w", err)
	}
	path, h := connectserver.NewExchangeServiceHandler(transport.NewExchangeHandler(d.exchange), svrOpts...)
	mux.Handle(path, h)
	// CatalogService keeps the raw generated mount (its per-contributor RFC 9421
	// verification runs in CatalogSignatureMiddleware, not the SDK seam) but shares
	// the ExchangeService codec + protovalidate contract through the raw-mount
	// options transport.CatalogMountOptions composes — the SAME shared validation
	// engine, helpers.SharedValidator, that the ExchangeService path composes
	// through connectserver.WithValidation, so the mounts cannot drift onto forked
	// rulesets — plus the message read cap, so the push endpoint, which accepts
	// contributor-supplied payloads, decodes under the same bound as every other
	// RPC. The integration harness calls the same function, so the cap the tests
	// drive is the cap that ships. A construction failure is a boot-time config
	// fault: surfaced up the boot chain (run() → main()) so the process exits
	// non-zero, not a panic.
	catalogOpts, err := transport.CatalogMountOptions(d.audience)
	if err != nil {
		return fmt.Errorf("catalog mount options: %w", err)
	}
	cpath, ch := rampconnect.NewCatalogServiceHandler(
		transport.NewCatalogHandler(d.catalog, d.agentRegistry), catalogOpts...,
	)
	mux.Handle(cpath, ch)
	return nil
}

// exchangeSupportedProfiles is the single source of truth for the extension
// profiles the Exchange advertises (WellKnownManifest.supported_profiles) AND
// projects on the discovery path (service.ExchangeConfig).
// ramp-comp-v1 renders the CoMP projection; ramp-news-v1 predates it.
func exchangeSupportedProfiles() []string {
	return []string{"ramp-news-v1", "ramp-comp-v1"}
}

func registerWellKnown(mux *http.ServeMux, d muxDeps) (server.Handlers, error) {
	hops := exchangeMaxIntermediaryHops()
	// Endpoint is the ExchangeService ORIGIN (e.g. http://exchange:8081), NOT a
	// service path: the manifest's top-level endpoint (WellKnownManifest.endpoint)
	// is what a broker's well-known resolver reads to route a re-packaged execute,
	// and Connect appends "/ramp.v1.ExchangeService/<Method>" to that origin
	// itself. A service-path value would double the path. Sourced from
	// EXCHANGE_PUBLIC_ORIGIN (default https://<EXCHANGE_DOMAIN>); CatalogEndpoint
	// likewise rides the origin.
	domain := exchangeDomain()
	origin := runhttp.EnvOr("EXCHANGE_PUBLIC_ORIGIN", "https://"+domain)
	wk, err := wellknown.New(wellknown.Config{
		Domain:                 domain,
		Endpoint:               origin,
		CatalogEndpoint:        origin,
		BaseCurrency:           d.ledgerCurrency,
		SupportedProfiles:      exchangeSupportedProfiles(),
		MaxIntermediaryHops:    &hops,
		TermsURI:               d.registration.termsURI,
		TermsDigest:            d.registration.termsDigest,
		RegistrationDataSchema: d.registration.schema,
		OfferKey:               d.offerSigner.PublicKey(),
		Clock:                  clock.System{},
		KeyLifetime:            wellknown.OfferKeyLifetime,
	})
	if err != nil {
		// The terms pair is the half an operator sets by hand, and its rules live
		// in the protocol as protovalidate constraints on the manifest message.
		// They fire two layers down and report a constraint violation on a
		// manifest field, naming neither variable. Name them here so the boot
		// failure points at what to edit.
		return server.Handlers{}, fmt.Errorf("register well-known (EXCHANGE_TERMS_URI=%q EXCHANGE_TERMS_DIGEST=%q): %w",
			d.registration.termsURI, d.registration.termsDigest, err)
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

// Package main is the Exchange service entrypoint.
//
// The Exchange implements ramp.v1.ExchangeService and ramp.v1.CatalogService:
// catalog lookup, Ed25519 offer signing, transaction execution with a
// write-before-sign invariant, signed URL minting (Ed25519 or RSA CloudFront
// per tenant), and usage reporting.
package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/wellknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(context.Background(), logger); err != nil {
		logger.Error("exchange exit", "err", err)
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
		return err
	}
	if pool == nil {
		logger.Warn("exchange running without database (EXCHANGE_DSN unset)")
		runhttp.Serve("exchange", runhttp.EnvOr("EXCHANGE_ADDR", ":8081"), healthzOnly(pool), logger)
		return nil
	}
	defer pool.Close()

	keys, err := setupDemoKeys(logger)
	if err != nil {
		return err
	}
	offerSigner, keystore := keys.offerSigner, keys.keystore

	// One SSRF-guarded HTTP client backs every outbound .well-known fetch:
	// agent registration, catalog contributor-authz, and the broker revocation
	// poll. It refuses loopback/link-local/private destinations unless
	// RAMP_FETCH_INSECURE_ALLOW_PRIVATE is set (compose/dev only).
	fetchClient := rampwellknown.NewGuardedClientFromEnv()

	queries := sqlc.New(pool)
	agentRegistry := agentreg.New(agentreg.Config{
		Repo:   repo.NewAgentRepo(queries),
		HTTP:   fetchClient,
		Scheme: runhttp.EnvOr("RAMP_MANIFEST_FETCH_SCHEME", ""),
		Port:   runhttp.EnvOr("RAMP_MANIFEST_FETCH_PORT", ""),
	})
	// EXCHANGE_CATALOG_URI_SCHEME defaults to https; compose overrides to http
	// so catalog URIs route through the in-network edge worker.
	service.SetCatalogURIScheme(runhttp.EnvOr("EXCHANGE_CATALOG_URI_SCHEME", ""))
	catalogSvc := service.NewCatalogService(
		repo.NewCatalogRepo(queries), agentRegistry, newManifestCache(fetchClient), db.PoolRunner{Pool: pool},
	)
	if err := catalogSvc.Bootstrap(ctx); err != nil {
		return err
	}
	exchangeSvc := buildExchange(buildSvcDeps{
		pool:          pool,
		queries:       queries,
		catalog:       catalogSvc,
		offerSigner:   offerSigner,
		keystore:      keystore,
		billing:       selectBillingAdapter(logger),
		agentRegistry: agentRegistry,
	})
	mux := buildMux(muxDeps{
		pool:          pool,
		exchange:      exchangeSvc,
		catalog:       catalogSvc,
		agentRegistry: agentRegistry,
		offerSigner:   offerSigner,
	})

	wrapped, err := buildWrapped(ctx, logger, mux, fetchClient)
	if err != nil {
		return err
	}
	runhttp.Serve("exchange", runhttp.EnvOr("EXCHANGE_ADDR", ":8081"), wrapped, logger)
	return nil
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
}

// buildExchange wires the ExchangeService that serves the canonical
// DiscoverResources / ExecuteTransaction / ReportUsage RPCs. The deprecated
// OffersService (ye6f-9 ListOffers / AcceptOffer / Report) was removed in
// W3 of t3vk.
func buildExchange(d buildSvcDeps) *service.ExchangeService {
	return service.NewExchangeService(service.ExchangeDeps{
		TxRunner:     db.PoolRunner{Pool: d.pool},
		Catalog:      d.catalog,
		Tenants:      repo.NewTenantRepo(d.queries),
		Agents:       repo.NewAgentRepo(d.queries),
		AgentReg:     d.agentRegistry,
		Transactions: repo.NewTransactionRepo(d.queries),
		Obligations:  repo.NewObligationRepo(d.queries),
		Billing:      d.billing,
		OfferSigner:  d.offerSigner,
		KeyStore:     d.keystore,
		Clk:          clock.System{},
		Config: service.ExchangeConfig{
			Exchange: runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local"),
		},
	})
}

// demoKeys bundles the Ed25519 + RSA key material setupDemoKeys returns; a
// struct keeps the run() call site readable and within line-length limits.
type demoKeys struct {
	offerSigner *signing.Ed25519Signer
	keystore    *signing.InMemoryKeyStore
	rsaPriv     *rsa.PrivateKey
	rsaKid      string
}

// setupDemoKeys resolves the demo Ed25519 + RSA key material used by offer
// signing, URL signing, and the AWS_CLOUDFRONT_RSA tenant scheme. Extracted
// from run() to keep run() under the funlen cap.
func setupDemoKeys(logger *slog.Logger) (*demoKeys, error) {
	demoPub, demoPriv, err := resolveEd25519Key(logger)
	if err != nil {
		return nil, err
	}
	offerSigner, err := signing.NewEd25519Signer(demoPub, demoPriv)
	if err != nil {
		return nil, err
	}
	keystore := signing.NewInMemoryKeyStore()
	demoKeyRef := runhttp.EnvOr("RAMP_DEMO_ED25519_KEY_REF", "exchange-primary")
	keystore.PutEd25519(demoKeyRef, demoPub, demoPriv)
	demoRSARef := runhttp.EnvOr("RAMP_DEMO_RSA_KEY_REF", "cf-rsa-primary")
	rsaPriv, err := resolveRSAKey(logger)
	if err != nil {
		return nil, err
	}
	keystore.PutRSA(demoRSARef, rsaPriv)
	return &demoKeys{offerSigner: offerSigner, keystore: keystore, rsaPriv: rsaPriv, rsaKid: demoRSARef}, nil
}

// buildWrapped builds the Exchange's final HTTP handler stack —
// RequestIDMiddleware + RFC 9421 httpsig.Middleware +
// CatalogSignatureMiddleware + mux — keeping run() below the funlen cap.
//
// The global httpsig middleware resolves keyids against the RAMP_KEYS_FILE
// JWKS (Broker relay, registered exchanges). Every /ramp.* request MUST
// be signed (see exchangeGlobalSigRequestPredicate); CatalogService paths
// run their own per-contributor signer in CatalogHandler.verifyCallerSignature
// (with lazy ramp.json self-signup) and are excluded from this gate.
// Integration tests mirror this wiring via startExchangeServer (T10).
//
// The biscuit/JWT transport middlewares (EntitlementMiddleware,
// AgentJWTMiddleware) were removed in e2k7h.7 alongside the entire
// entitlement/delegation surface; identity for v1 is the RFC 9421
// signature keyid, full stop.
func buildWrapped(
	ctx context.Context, logger *slog.Logger, mux http.Handler, fetchClient rampwellknown.HTTPDoer,
) (http.Handler, error) {
	resolver, replay, err := buildHTTPSigDeps(ctx, logger, fetchClient)
	if err != nil {
		return nil, err
	}
	// MaxSignatures bounds the relay chain depth at the Exchange terminal: the
	// published max_intermediary_hops counts intermediaries, so the signature
	// count ceiling is that plus the originating agent's own signature (RAMP-56).
	maxSignatures := int(exchangeMaxIntermediaryHops()) + 1
	return transport.WrapPublicSurface(logger, resolver, replay, maxSignatures, mux), nil
}

// muxDeps collects everything buildMux needs so run() can stay linear and
// tests can assemble the Exchange's HTTP surface without booting real services.
type muxDeps struct {
	pool          interface{ Ping(context.Context) error }
	exchange      *service.ExchangeService
	catalog       *service.CatalogService
	agentRegistry agentreg.Registry
	offerSigner   *signing.Ed25519Signer
}

// buildMux wires the Exchange's HTTP surface: healthz, Connect-Go RPCs, the
// well-known endpoints, and the public agents/register route. Admin-plane
// endpoints have been removed (design-demo-bootstrap.md §9); any request to
// /admin/* falls through to http.ServeMux's 404.
func buildMux(d muxDeps) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthzHandler(d.pool))
	registerConnect(mux, d.exchange, d.catalog, d.agentRegistry)
	registerWellKnown(mux, d.offerSigner)
	transport.NewAgentsRegisterHandler(d.agentRegistry, transport.AgentsRegisterOptions{}).
		RegisterRoutes(mux)
	return mux
}

// selectBillingAdapter chooses the Adapter at boot. RAMP_BILLING_ADAPTER=free
// (default) returns billing.FreeAdapter{}; the always-approve zero-state
// adapter appropriate for demo / wholesale tiers. =inmemory returns the
// prepaid-balance InMemoryAdapter seeded from EXCHANGE_BILLING_SEED. Unknown
// values fall back to free with a warning.
func selectBillingAdapter(logger *slog.Logger) billing.Adapter {
	switch kind := runhttp.EnvOr("RAMP_BILLING_ADAPTER", "free"); kind {
	case "free":
		return billing.FreeAdapter{}
	case "inmemory":
		return newBillingAdapter(logger)
	default:
		logger.Warn("RAMP_BILLING_ADAPTER unknown value; using free", "value", kind)
		return billing.FreeAdapter{}
	}
}

// newBillingAdapter builds the in-memory billing adapter, optionally seeded
// with demo agent balances from EXCHANGE_BILLING_SEED — a JSON object of the
// shape `{"agent-id": {"value": "100.00", "currency": "USD"}}`. Malformed
// entries are logged and skipped so a typo can't wedge the whole service.
func newBillingAdapter(logger *slog.Logger) *billing.InMemoryAdapter {
	seed := billing.InMemoryOptions{Balances: map[string]billing.Amount{}}
	raw := runhttp.EnvOr("EXCHANGE_BILLING_SEED", "")
	if raw == "" {
		return billing.NewInMemoryAdapter(seed)
	}
	var parsed map[string]struct {
		Value    string `json:"value"`
		Currency string `json:"currency"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		logger.Warn("EXCHANGE_BILLING_SEED ignored: invalid JSON", "err", err)
		return billing.NewInMemoryAdapter(seed)
	}
	for agentID, amt := range parsed {
		a, err := billing.NewAmount(amt.Value, amt.Currency)
		if err != nil {
			logger.Warn("EXCHANGE_BILLING_SEED entry skipped", "agent_id", agentID, "err", err)
			continue
		}
		seed.Balances[agentID] = a
	}
	logger.Info("billing adapter seeded", "agents", len(seed.Balances))
	return billing.NewInMemoryAdapter(seed)
}

func registerConnect(
	mux *http.ServeMux,
	m *service.ExchangeService,
	c *service.CatalogService,
	reg agentreg.Registry,
) {
	base := transport.NewExchangeHandler(m)
	// Override Connect's default JSON codec so scalar zero values
	// appear in the wire output. The default protojson behavior omits
	// them, which hides zero-valued observables (e.g. unit_cost=0) that
	// agents and obligation tests depend on.
	codecOpt := connect.WithCodec(transport.EmitUnpopulatedJSONCodec())
	path, h := rampconnect.NewExchangeServiceHandler(base, codecOpt)
	mux.Handle(path, h)
	cpath, ch := rampconnect.NewCatalogServiceHandler(transport.NewCatalogHandler(c, reg), codecOpt)
	mux.Handle(cpath, ch)
}

func registerWellKnown(mux *http.ServeMux, signer *signing.Ed25519Signer) {
	now := clock.System{}.Now()
	hops := exchangeMaxIntermediaryHops()
	wk, err := wellknown.New(wellknown.Config{
		Domain:              runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local"),
		Endpoint:            "/ramp.v1.ExchangeService",
		CatalogEndpoint:     "/ramp.v1.CatalogService",
		BaseCurrency:        "USD",
		SupportedProfiles:   []string{"ramp-news-v1"},
		MaxIntermediaryHops: &hops,
		OfferKeyID:          runhttp.EnvOr("RAMP_DEMO_ED25519_KEY_REF", "exchange-primary"),
		OfferKey:            signer.PublicKey(),
		KeyNotBefore:        now,
		KeyNotAfter:         now.Add(10 * 365 * 24 * time.Hour),
	})
	if err != nil {
		panic(err)
	}
	wk.RegisterRoutes(mux)
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

func healthzOnly(pool interface{ Ping(context.Context) error }) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthzHandler(pool))
	return mux
}

// newManifestCache builds the publisher-manifest cache over the shared
// SSRF-guarded fetch client. Honors RAMP_MANIFEST_FETCH_{SCHEME,PORT} for
// docker-compose / local-dev stacks; production leaves both unset (defaults to
// https + scheme-default port). ExpectRole pins every fetched manifest to
// ROLE_PUBLISHER so a misrouted document (e.g. an agent or exchange manifest)
// is rejected at the cache.
func newManifestCache(client rampwellknown.HTTPDoer) *rampwellknown.Cache {
	return rampwellknown.NewCache(rampwellknown.CacheOptions{
		Client:     client,
		Scheme:     runhttp.EnvOr("RAMP_MANIFEST_FETCH_SCHEME", ""),
		Port:       runhttp.EnvOr("RAMP_MANIFEST_FETCH_PORT", ""),
		ExpectRole: rampwellknown.RolePublisher,
	})
}

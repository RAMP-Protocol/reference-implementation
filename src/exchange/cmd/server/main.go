// Package main is the Exchange service entrypoint.
//
// The Exchange implements ramp.v1.ExchangeService and ramp.v1.CatalogService:
// catalog lookup, Ed25519 offer signing, transaction execution with a
// write-before-sign invariant, signed URL minting (Ed25519 or RSA CloudFront
// per tenant), and usage reporting.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"

	rampconnect "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
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
	defer pool.Close()

	// Single Ed25519 keypair for both offer signing and demo URL signing so the
	// JWKS endpoint publishes a public key the edge worker can verify both with.
	// See keys.go for env-vs-generate resolution (RAMP_ED25519_PRIVATE_PEM).
	demoPub, demoPriv, err := resolveEd25519Key(logger)
	if err != nil {
		return err
	}
	offerSigner, err := signing.NewEd25519Signer(demoPub, demoPriv)
	if err != nil {
		return err
	}
	keystore := signing.NewInMemoryKeyStore()
	demoKeyRef := runhttp.EnvOr("RAMP_DEMO_ED25519_KEY_REF", "exchange-primary")
	keystore.PutEd25519(demoKeyRef, demoPub, demoPriv)

	// RSA key for the AWS_CLOUDFRONT_RSA tenant scheme. The public key PEM is
	// served at /admin/keys/rsa-public.pem so a local CloudFront-compat verifier
	// (aws-edge shim) can bootstrap without any AWS credentials.
	demoRSARef := runhttp.EnvOr("RAMP_DEMO_RSA_KEY_REF", "cf-rsa-primary")
	rsaPriv, err := resolveRSAKey(logger)
	if err != nil {
		return err
	}
	keystore.PutRSA(demoRSARef, rsaPriv)

	queries := sqlc.New(pool)
	catalogSvc := service.NewCatalogService(repo.NewCatalogRepo(queries))
	if err := catalogSvc.Bootstrap(ctx); err != nil {
		return err
	}
	mp := service.NewMarketplaceService(service.MarketplaceDeps{
		Pool:         pool,
		Catalog:      catalogSvc,
		Tenants:      repo.NewTenantRepo(queries),
		Agents:       repo.NewAgentRepo(queries),
		Transactions: repo.NewTransactionRepo(queries),
		Obligations:  repo.NewObligationRepo(queries),
		Billing:      newBillingAdapter(logger),
		OfferSigner:  offerSigner,
		KeyStore:     keystore,
		Config: service.MarketplaceConfig{
			Marketplace: runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local"),
		},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthzHandler(pool))
	mux.HandleFunc("POST /admin/catalog/reload", catalogReloadHandler(catalogSvc, logger))
	mux.HandleFunc("POST /admin/seed", seedHandler(queries, catalogSvc, logger))
	mux.HandleFunc("GET /admin/catalog", catalogListHandler(repo.NewCatalogRepo(queries)))
	mux.HandleFunc("GET /admin/keys/rsa-public.pem", rsaPublicKeyHandler(&rsaPriv.PublicKey))
	mux.HandleFunc("GET /admin/ledger", ledgerHandler(
		repo.NewTransactionRepo(queries),
		repo.NewObligationRepo(queries),
		repo.NewTenantRepo(queries),
	))
	registerConnect(mux, mp, catalogSvc)
	registerWellKnown(mux, offerSigner)

	wrapped := transport.RequestIDMiddleware(logger, mux)
	runhttp.Serve("exchange", runhttp.EnvOr("EXCHANGE_ADDR", ":8081"), wrapped, logger)
	return nil
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

func registerConnect(mux *http.ServeMux, m *service.MarketplaceService, c *service.CatalogService) {
	path, h := rampconnect.NewExchangeServiceHandler(transport.NewExchangeHandler(m))
	mux.Handle(path, h)
	cpath, ch := rampconnect.NewCatalogServiceHandler(transport.NewCatalogHandler(c))
	mux.Handle(cpath, ch)
}

func registerWellKnown(mux *http.ServeMux, signer *signing.Ed25519Signer) {
	wk := wellknown.New(wellknown.Manifest{
		Exchange:           runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local"),
		Version:            "1.0",
		ExchangeServiceURL: "/ramp.v1.ExchangeService",
		CatalogServiceURL:  "/ramp.v1.CatalogService",
		JWKSURL:            "/marketplace/v1/keys",
		BaseCurrency:       "USD",
	}, signer.PublicKey(), "exchange-primary")
	wk.RegisterRoutes(mux)
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

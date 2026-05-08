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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"

	rampconnect "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"

	"github.com/jackc/pgx/v5/pgtype"

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
	if pool == nil {
		logger.Warn("exchange running without database (EXCHANGE_DSN unset)")
		runhttp.Serve("exchange", runhttp.EnvOr("EXCHANGE_ADDR", ":8081"), healthzOnly(pool), logger)
		return nil
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

// rsaPublicKeyHandler serves the current demo RSA public key in PEM form so
// a local CloudFront-compatible verifier can bootstrap without AWS creds.
// Unauth, demo-only; production routes this via IAM + Secrets Manager.
func rsaPublicKeyHandler(pub *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_ = pem.Encode(w, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
}

// seedRequest is the body shape for POST /admin/seed — a one-shot demo helper
// that inserts tenants + agents + catalog rows and then rebuilds the radix
// trie. Gated to the admin path and intended for local / demo deployments only.
type seedRequest struct {
	Tenants []seedTenant  `json:"tenants"`
	Agents  []seedAgent   `json:"agents"`
	Catalog []seedCatalog `json:"catalog"`
}

// seedAgent registers a row in ramp.agents so transaction_log FK lookups
// resolve. Demo-only — production agents register via DCR / a separate
// onboarding flow that captures their public key for signature verification.
type seedAgent struct {
	AgentID       string `json:"agent_id"`
	PublicKey     string `json:"public_key"`     // base64 (PEM strip-down) or any opaque tag
	ManifestURL   string `json:"manifest_url"`
	RequesterType string `json:"requester_type"` // AGENT | HUMAN_TOOL | SERVICE | DELEGATED | RESEARCH
}

type seedTenant struct {
	TenantID            string `json:"tenant_id"`
	Domain              string `json:"domain"`
	HmacSecretRef       string `json:"hmac_secret_ref"`
	Ed25519KeyRef       string `json:"ed25519_key_ref"`
	SigningScheme       string `json:"signing_scheme"`
	RSAKeyRef           string `json:"rsa_key_ref"`
	CloudFrontKeyPairID string `json:"cloudfront_key_pair_id"`
}

type seedCatalog struct {
	ResourceID     string          `json:"resource_id"`
	TenantID       string          `json:"tenant_id"`
	URI            string          `json:"uri"`
	URIPrefix      string          `json:"uri_prefix"`
	Pricing        json.RawMessage `json:"pricing"`
	LicensingRules json.RawMessage `json:"licensing_rules"`
	DeliveryMethod string          `json:"delivery_method"`
}

// seedHandler inserts tenants + catalog entries and rebuilds the radix trie.
// Duplicate tenant inserts are tolerated (logged, not fatal); catalog entries
// use Upsert so re-seeding is idempotent.
func seedHandler(queries sqlc.Querier, catalogSvc *service.CatalogService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req seedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, t := range req.Tenants {
			scheme := sqlc.RampSigningScheme(t.SigningScheme)
			if scheme == "" {
				scheme = sqlc.RampSigningSchemeED25519
			}
			_, err := queries.InsertTenant(r.Context(), sqlc.InsertTenantParams{
				TenantID:            t.TenantID,
				Domain:              t.Domain,
				HmacSecretRef:       t.HmacSecretRef,
				Ed25519KeyRef:       t.Ed25519KeyRef,
				ReportingPolicy:     []byte("{}"),
				SigningScheme:       scheme,
				RsaKeyRef:           pgtype.Text{String: t.RSAKeyRef, Valid: t.RSAKeyRef != ""},
				CloudfrontKeyPairID: pgtype.Text{String: t.CloudFrontKeyPairID, Valid: t.CloudFrontKeyPairID != ""},
			})
			if err != nil {
				logger.WarnContext(r.Context(), "seed: insert tenant skipped", "tenant_id", t.TenantID, "err", err)
			}
		}
		for _, a := range req.Agents {
			rt := sqlc.RampRequesterType(a.RequesterType)
			if rt == "" {
				rt = sqlc.RampRequesterType("AGENT")
			}
			if _, err := queries.UpsertAgent(r.Context(), sqlc.UpsertAgentParams{
				AgentID:       a.AgentID,
				PublicKey:     []byte(a.PublicKey),
				ManifestUrl:   pgtype.Text{String: a.ManifestURL, Valid: a.ManifestURL != ""},
				RequesterType: rt,
			}); err != nil {
				logger.ErrorContext(r.Context(), "seed: upsert agent", "agent_id", a.AgentID, "err", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		for _, c := range req.Catalog {
			pricing := []byte(c.Pricing)
			if len(pricing) == 0 {
				pricing = []byte("{}")
			}
			rules := []byte(c.LicensingRules)
			if len(rules) == 0 {
				rules = []byte("{}")
			}
			dm := sqlc.RampDeliveryMethod(c.DeliveryMethod)
			if dm == "" {
				dm = sqlc.RampDeliveryMethodDIRECT
			}
			if _, err := queries.UpsertCatalogEntry(r.Context(), sqlc.UpsertCatalogEntryParams{
				ResourceID:     c.ResourceID,
				TenantID:       c.TenantID,
				Uri:            c.URI,
				UriPrefix:      c.URIPrefix,
				Pricing:        pricing,
				LicensingRules: rules,
				DeliveryMethod: dm,
			}); err != nil {
				logger.ErrorContext(r.Context(), "seed: upsert catalog", "resource_id", c.ResourceID, "err", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if err := catalogSvc.Bootstrap(r.Context()); err != nil {
			logger.ErrorContext(r.Context(), "seed: bootstrap", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// catalogListHandler exposes GET /admin/catalog — flat JSON dump of catalog rows
// (no paging, demo-only). Pricing + licensing columns are returned as raw JSON
// so consumers see the shape the service stored.
func catalogListHandler(r repo.CatalogRepo) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		rows, err := r.ListAll(req.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type row struct {
			ResourceID     string          `json:"resource_id"`
			TenantID       string          `json:"tenant_id"`
			URI            string          `json:"uri"`
			URIPrefix      string          `json:"uri_prefix"`
			Pricing        json.RawMessage `json:"pricing"`
			LicensingRules json.RawMessage `json:"licensing_rules"`
			DeliveryMethod string          `json:"delivery_method"`
		}
		out := make([]row, 0, len(rows))
		for _, e := range rows {
			out = append(out, row{
				ResourceID: e.ResourceID, TenantID: e.TenantID,
				URI: e.URI, URIPrefix: e.URIPrefix,
				Pricing: json.RawMessage(e.PricingJSON), LicensingRules: json.RawMessage(e.LicensingJSON),
				DeliveryMethod: e.DeliveryMethod,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// catalogReloadHandler exposes POST /admin/catalog/reload for demo / E2E use.
// Triggers CatalogService.Bootstrap to rebuild the in-process radix trie from
// the current DB contents. Production deployments would gate this behind IAM
// and require authentication; here it is unauth (demo only).
func catalogReloadHandler(c *service.CatalogService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := c.Bootstrap(r.Context()); err != nil {
			logger.ErrorContext(r.Context(), "catalog reload failed", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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

func healthzOnly(pool interface{ Ping(context.Context) error }) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthzHandler(pool))
	return mux
}

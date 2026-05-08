//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	connect "connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	rampconnect "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// testHarness bundles the live server + handles used by each test.
type testHarness struct {
	t              *testing.T
	ctx            context.Context
	pool           *pgxpool.Pool
	queries        *sqlc.Queries
	offerSigner    *signing.Ed25519Signer
	catalog        *service.CatalogService
	marketplace    *service.MarketplaceService
	exchangeClient rampconnect.ExchangeServiceClient
	catalogClient  rampconnect.CatalogServiceClient
	server         *httptest.Server
	billing        *billing.InMemoryAdapter
	keystore       *signing.InMemoryKeyStore
	tenantID       string
	tenantDomain   string
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	ctx := context.Background()
	dsn := sharedb.StartPostgres(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool, err := sharedb.Setup(ctx, sharedb.SetupOptions{
		DSN:             dsn,
		Migrations:      exchangedb.Migrations,
		MigrationsDir:   exchangedb.MigrationsDir,
		MigrationsTable: exchangedb.MigrationsTable,
	}, logger)
	if err != nil {
		t.Fatalf("db setup: %v", err)
	}
	t.Cleanup(pool.Close)

	queries := sqlc.New(pool)
	tenantID := "t_" + uuid.NewString()
	tenantDomain := tenantID + ".example"

	keystore := signing.NewInMemoryKeyStore()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	ed25519Ref := "secret://ed25519/" + tenantID
	keystore.PutEd25519(ed25519Ref, pub, priv)

	if _, err := queries.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          tenantDomain,
		HmacSecretRef:   "unused",
		Ed25519KeyRef:   ed25519Ref,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := queries.UpsertAgent(ctx, sqlc.UpsertAgentParams{
		AgentID:       "agent-test",
		PublicKey:     []byte("stub-agent-key"),
		RequesterType: sqlc.RampRequesterTypeAGENT,
	}); err != nil {
		t.Fatalf("upsert agent: %v", err)
	}

	tenantsRepo := repo.NewTenantRepo(queries)
	agentsRepo := repo.NewAgentRepo(queries)
	catalogRepo := repo.NewCatalogRepo(queries)
	txRepo := repo.NewTransactionRepo(queries)
	oblRepo := repo.NewObligationRepo(queries)

	offerSigner, err := signing.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("offer signer: %v", err)
	}
	catalogSvc := service.NewCatalogService(catalogRepo)
	if err := catalogSvc.Bootstrap(ctx); err != nil {
		t.Fatalf("catalog bootstrap: %v", err)
	}
	bill := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{
			"agent-test": mustBillingAmount(t, "10.00", "USD"),
		},
	})
	mp := service.NewMarketplaceService(service.MarketplaceDeps{
		Pool:         pool,
		Catalog:      catalogSvc,
		Tenants:      tenantsRepo,
		Agents:       agentsRepo,
		Transactions: txRepo,
		Obligations:  oblRepo,
		Billing:      bill,
		OfferSigner:  offerSigner,
		KeyStore:     keystore,
		Config:       service.MarketplaceConfig{Marketplace: "exchange.ramp.test"},
	})

	mux := http.NewServeMux()
	exchangePath, exchangeHandler := rampconnect.NewExchangeServiceHandler(transport.NewExchangeHandler(mp))
	catalogPath, catalogHandler := rampconnect.NewCatalogServiceHandler(transport.NewCatalogHandler(catalogSvc))
	mux.Handle(exchangePath, exchangeHandler)
	mux.Handle(catalogPath, catalogHandler)

	server := httptest.NewServer(transport.RequestIDMiddleware(logger, mux))
	t.Cleanup(server.Close)

	return &testHarness{
		t:              t,
		ctx:            ctx,
		pool:           pool,
		queries:        queries,
		offerSigner:    offerSigner,
		catalog:        catalogSvc,
		marketplace:    mp,
		exchangeClient: rampconnect.NewExchangeServiceClient(server.Client(), server.URL, connect.WithGRPC()),
		catalogClient:  rampconnect.NewCatalogServiceClient(server.Client(), server.URL, connect.WithGRPC()),
		server:         server,
		billing:        bill,
		keystore:       keystore,
		tenantID:       tenantID,
		tenantDomain:   tenantDomain,
	}
}

func mustBillingAmount(t *testing.T, raw, ccy string) billing.Amount {
	t.Helper()
	a, err := billing.NewAmount(raw, ccy)
	if err != nil {
		t.Fatalf("NewAmount: %v", err)
	}
	return a
}

// stringPtr returns a pointer to s (generic proto optional-string helper).
func stringPtr(s string) *string { return &s }

// ceAs is a thin errors.As wrapper for *connect.Error to keep test ergonomics
// compact.
func ceAs(err error, target **connect.Error) bool {
	var ce *connect.Error
	if err == nil {
		return false
	}
	ok := errors.As(err, &ce)
	if ok {
		*target = ce
	}
	return ok
}

// tenantDrain returns an authorize request that subtracts the full seed
// balance so subsequent authorizations fail.
func tenantDrain(t *testing.T) billing.AuthorizeRequest {
	t.Helper()
	return billing.AuthorizeRequest{
		TenantID: "t", AgentID: "agent-test",
		UnitCost: mustBillingAmount(t, "10.00", "USD"),
		Quantity: 1, Unit: "access",
	}
}

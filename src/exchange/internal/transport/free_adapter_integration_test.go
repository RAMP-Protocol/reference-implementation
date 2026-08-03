//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/oklog/ulid/v2"

	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// TestFreeAdapter_DropInForExchangeService wires billing.FreeAdapter into
// ExchangeService and walks ExecuteTransaction end-to-end to prove the
// free adapter is a drop-in for the Adapter interface: the hot path behaves
// identically to the prepaid adapter, a transaction_log row is written, and
// the response carries the ULID BillingID minted by FreeAdapter.
func TestFreeAdapter_DropInForExchangeService(t *testing.T) {
	h := newFreeAdapterHarness(t)
	ctx := h.ctx

	// Seed catalog via CatalogService.
	if _, err := h.catalogClient.PushResources(ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-free",
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.tenantDomain, Path: "/articles/free",
			// A priced term is required for an offer; the FreeAdapter
			// ignores the amount but the entry still needs a real term to price.
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	})); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Discover to get the signed offer.
	discovered, err := h.exchangeClient.DiscoverResources(ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:  "1.0",
		Uris: []string{"https://" + h.tenantDomain + "/articles/free"},
		Requester: &rampv1.Requester{
			Id: "agent-free", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	offers := discovered.Msg.GetOffers()
	if len(offers) != 1 {
		t.Fatalf("offers len = %d", len(offers))
	}
	offer := offers[0]

	requester := &rampv1.Requester{
		Id: "agent-free", Domain: "agent.example",
		Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	execResp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", IdempotencyKey: "tx-free",
		Requester: requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, "tx-free")},
		},
	}))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	item := singleResultItem(t, execResp)
	if item.GetTransactionId() == "" {
		t.Fatal("transaction id empty")
	}
	billingID := item.GetBillingId()
	if billingID == "" {
		t.Fatal("billing id empty in response")
	}
	if _, err := ulid.Parse(billingID); err != nil {
		t.Fatalf("billing id %q not a valid ULID: %v", billingID, err)
	}

	// Verify transaction log row was written with our billing ID, under the
	// DERIVED per-item key (items-only path).
	// Production repository surface, not the raw sqlc Querier (Testing Doctrine pt9).
	derivedKey := "tx-free" + ":" + offer.GetOfferId()
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(ctx, derivedKey)
	if err != nil {
		t.Fatalf("TransactionRepo.ByIdempotencyKey: %v", err)
	}
	if rec.IdempotencyKey != derivedKey {
		t.Fatalf("idempotency_key = %q", rec.IdempotencyKey)
	}
	if rec.BillingID != billingID {
		t.Fatalf("logged billing id = %q, response billing id = %q", rec.BillingID, billingID)
	}
	if len(rec.SignedURLHash) != 32 {
		t.Fatalf("signed_url_hash len = %d", len(rec.SignedURLHash))
	}
}

// freeAdapterHarness is a parallel harness to the shared testHarness that
// wires FreeAdapter instead of InMemoryAdapter. Kept minimal — only the
// surfaces exercised by the FreeAdapter drop-in test.
type freeAdapterHarness struct {
	ctx            context.Context
	queries        *sqlc.Queries
	exchangeClient rampconnect.ExchangeServiceClient
	catalogClient  rampconnect.CatalogServiceClient
	tenantID       string
	tenantDomain   string
	// callerPriv signs the body offer-acceptance with agent-free's registered
	// key.
	callerPriv ed25519.PrivateKey
}

func newFreeAdapterHarness(t *testing.T) *freeAdapterHarness {
	t.Helper()
	fx := setupExchangeTestDB(t, "agent-free")
	ctx, logger, pool, queries, keystore := fx.ctx, fx.logger, fx.pool, fx.queries, fx.keystore
	tenantID, tenantDomain := fx.tenantID, fx.tenantDomain

	offerSigner, err := signing.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("offer signer: %v", err)
	}

	callerID := "agent-free"
	// Sign with the seeded agent's key so the verified key matches the pinned
	// agents-row key for callerID (identity↔key binding).
	callerPub, callerPriv := fx.agentPub, fx.agentPriv
	registry := newAllowAllRegistry()
	registry.put(callerID, callerPub)
	manifests := newAllowAllManifestCache(callerID)

	srv := startExchangeServer(t, exchangeServerDeps{
		pool: pool, queries: queries, registry: registry, manifests: manifests,
		bill: billing.FreeAdapter{}, signer: offerSigner, keystore: keystore, logger: logger,
		httpsigKeys: map[string]ed25519.PublicKey{rwtestutil.MustThumbprintPriv(callerPriv): callerPub},
		// The seeded tenant doubles as the default tenant Register reads its
		// activation policy from, so agent-free can billing-register
		// before its paid transaction. billingRefGen stays nil → uuid (the
		// FreeAdapter keeps no ledger, so the ref value is never asserted).
		defaultTenantDomain: tenantDomain,
	})
	if err := srv.catalogSvc.Bootstrap(ctx); err != nil {
		t.Fatalf("catalog bootstrap: %v", err)
	}

	signingClient := &http.Client{Transport: newSigningTransport(srv.baseTransport, callerID, callerPriv)}
	exchangeClient := rampconnect.NewExchangeServiceClient(signingClient, srv.server.URL, connect.WithGRPC())
	// agent-free is seeded with an agents row but no billing_ref; the paid
	// transaction the test drives needs one, so register it for billing
	// through the public Register RPC.
	registerCaller(t, ctx, exchangeClient)

	return &freeAdapterHarness{
		ctx:            ctx,
		queries:        queries,
		exchangeClient: exchangeClient,
		catalogClient:  rampconnect.NewCatalogServiceClient(signingClient, srv.server.URL, connect.WithGRPC()),
		tenantID:       tenantID,
		tenantDomain:   tenantDomain,
		callerPriv:     callerPriv,
	}
}

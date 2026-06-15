//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/oklog/ulid/v2"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
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
		Entries:  []*rampv1.ResourceEntry{{Domain: h.tenantDomain, Path: "/articles/free"}},
	})); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Discover to get the signed offer.
	discovered, err := h.exchangeClient.DiscoverResources(ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Id: "q-free",
		Requester: &rampv1.Requester{
			Id: "agent-free", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris: []string{"https://" + h.tenantDomain + "/articles/free"},
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

	offerID := offer.GetOfferId()
	offerSig := offer.GetSignature()
	execResp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-free",
		OfferId:        &offerID,
		OfferSignature: &offerSig,
		Requester: &rampv1.Requester{
			Id: "agent-free", Domain: "agent.example",
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execResp.Msg.GetTransactionId() == "" {
		t.Fatal("transaction id empty")
	}
	billingID := execResp.Msg.GetBillingId()
	if billingID == "" {
		t.Fatal("billing id empty in response")
	}
	if _, err := ulid.Parse(billingID); err != nil {
		t.Fatalf("billing id %q not a valid ULID: %v", billingID, err)
	}

	// Verify transaction log row was written with our billing ID.
	row, err := h.queries.GetTransactionByRequestID(ctx, "tx-free")
	if err != nil {
		t.Fatalf("GetTransactionByRequestID: %v", err)
	}
	if row.TxRequestID != "tx-free" {
		t.Fatalf("tx_request_id = %q", row.TxRequestID)
	}
	if !row.BillingID.Valid || row.BillingID.String != billingID {
		t.Fatalf("logged billing id = %+v, response billing id = %q", row.BillingID, billingID)
	}
	if len(row.SignedUrlHash) != 32 {
		t.Fatalf("signed_url_hash len = %d", len(row.SignedUrlHash))
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
	callerPub, callerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("caller ed25519: %v", err)
	}
	registry := newAllowAllRegistry()
	registry.put(callerID, callerPub)
	manifests := &allowAllManifestCache{caller: callerID}

	srv := startExchangeServer(t, exchangeServerDeps{
		pool: pool, queries: queries, registry: registry, manifests: manifests,
		bill: billing.FreeAdapter{}, signer: offerSigner, keystore: keystore, logger: logger,
		httpsigKeys: map[string]ed25519.PublicKey{callerID: callerPub},
	})
	if err := srv.catalogSvc.Bootstrap(ctx); err != nil {
		t.Fatalf("catalog bootstrap: %v", err)
	}

	signingClient := &http.Client{Transport: newSigningTransport(srv.baseTransport, callerID, callerPriv)}

	return &freeAdapterHarness{
		ctx:            ctx,
		queries:        queries,
		exchangeClient: rampconnect.NewExchangeServiceClient(signingClient, srv.server.URL, connect.WithGRPC()),
		catalogClient:  rampconnect.NewCatalogServiceClient(signingClient, srv.server.URL, connect.WithGRPC()),
		tenantID:       tenantID,
		tenantDomain:   tenantDomain,
	}
}

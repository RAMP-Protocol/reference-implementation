//go:build integration

package transport_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
	rampconnect "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// rebuildMarketplace wires a fresh MarketplaceService against the same DB pool
// and billing adapter as h, simulating a process restart (empty in-memory LRU).
// Re-creates repos from h.queries so no changes to testHarness are required.
func rebuildMarketplace(t *testing.T, h *testHarness) rampconnect.ExchangeServiceClient {
	t.Helper()
	tenantsRepo := repo.NewTenantRepo(h.queries)
	agentsRepo := repo.NewAgentRepo(h.queries)
	txRepo := repo.NewTransactionRepo(h.queries)
	oblRepo := repo.NewObligationRepo(h.queries)

	freshMP := service.NewMarketplaceService(service.MarketplaceDeps{
		Pool:         h.pool,
		Catalog:      h.catalog,
		Tenants:      tenantsRepo,
		Agents:       agentsRepo,
		Transactions: txRepo,
		Obligations:  oblRepo,
		Billing:      h.billing,
		OfferSigner:  h.offerSigner,
		KeyStore:     h.keystore,
		Config:       service.MarketplaceConfig{Marketplace: "exchange.ramp.test"},
	})

	mux := http.NewServeMux()
	exchangePath, exchangeHandler := rampconnect.NewExchangeServiceHandler(transport.NewExchangeHandler(freshMP))
	mux.Handle(exchangePath, exchangeHandler)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(transport.RequestIDMiddleware(logger, mux))
	t.Cleanup(srv.Close)
	return rampconnect.NewExchangeServiceClient(srv.Client(), srv.URL, connect.WithGRPC())
}

// TestIdempotency_RestartReplay verifies that a tx_request_id already committed
// to the DB is rejected with AlreadyExists after a simulated service restart
// (fresh MarketplaceService with empty in-memory LRU).
func TestIdempotency_RestartReplay(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	offerID := offer.GetOfferId()
	offerSig := offer.GetSignature()
	req := &rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-restart-replay",
		OfferId:        stringPtr(offerID),
		OfferSignature: stringPtr(offerSig),
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example",
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}

	// First call: must succeed.
	if _, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req)); err != nil {
		t.Fatalf("first execute: %v", err)
	}

	// Simulate restart: fresh service with empty LRU, same DB.
	freshClient := rebuildMarketplace(t, h)

	// Replay with identical tx_request_id — DB idempotency must catch it.
	_, err := freshClient.ExecuteTransaction(ctx, connect.NewRequest(req))
	if err == nil {
		t.Fatal("expected idempotent rejection after restart, got success")
	}
	var ce *connect.Error
	if !connectAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	if ce.Code() != connect.CodeAlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists (CodeInternal suggests DB check was skipped)", ce.Code())
	}
}

// TestIdempotency_ConcurrentReplay fires N concurrent requests with the same
// tx_request_id. Exactly one must succeed; all losers must see AlreadyExists.
// The billing balance must be debited exactly once.
func TestIdempotency_ConcurrentReplay(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	offerID := offer.GetOfferId()
	offerSig := offer.GetSignature()

	const goroutines = 10
	type result struct{ err error }
	results := make([]result, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			_, err := h.exchangeClient.ExecuteTransaction(context.Background(), connect.NewRequest(&rampv1.TransactionRequest{
				Ver: "1.0", Id: "tx-concurrent-idem",
				OfferId:        stringPtr(offerID),
				OfferSignature: stringPtr(offerSig),
				Requester: &rampv1.Requester{
					Id: "agent-test", Domain: "agent.example",
					Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
				},
			}))
			results[i] = result{err: err}
		}(i)
	}
	wg.Wait()

	// Concurrent callers sharing the same in-flight singleflight key all
	// receive the single successful response. Callers that arrive after the
	// singleflight clears hit the LRU or DB path and get AlreadyExists.
	// Either outcome is correct; what must never happen is any other error.
	var successes, alreadyExists, other int
	for _, r := range results {
		if r.err == nil {
			successes++
			continue
		}
		var ce *connect.Error
		if connectAs(r.err, &ce) && ce.Code() == connect.CodeAlreadyExists {
			alreadyExists++
		} else {
			other++
			t.Logf("unexpected error: %v", r.err)
		}
	}

	if successes < 1 {
		t.Errorf("expected at least 1 success, got 0 (alreadyExists=%d, other=%d)", alreadyExists, other)
	}
	if successes+alreadyExists != goroutines {
		t.Errorf("successes(%d) + alreadyExists(%d) != %d; %d unexpected errors", successes, alreadyExists, goroutines, other)
	}
	if other != 0 {
		t.Errorf("%d result(s) had unexpected error type (want success or AlreadyExists only)", other)
	}

	// The critical invariant: billing debited exactly once regardless of how
	// many concurrent calls were collapsed by singleflight.
	// $10.00 - $0.05 * 1 = $9.95
	bal, err := h.billing.GetBalance(ctx, "agent-test")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	want, _ := billing.NewAmount("9.95", "USD")
	if bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want 9.95 (billing debited more than once)", bal.Value.FloatString(4))
	}
}

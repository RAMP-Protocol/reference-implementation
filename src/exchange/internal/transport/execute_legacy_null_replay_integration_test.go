//go:build integration

package transport_test

import (
	"context"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

func signedExecuteRequest(
	t *testing.T, h *testHarness, idem string, offers ...*rampv1.Offer,
) *rampv1.TransactionRequest {
	t.Helper()
	requester := newRequester("agent-test", "agent.example")
	items := make([]*rampv1.TransactionItem, 0, len(offers))
	for _, offer := range offers {
		items = append(items, &rampv1.TransactionItem{
			Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, idem),
		})
	}
	req := &rampv1.TransactionRequest{
		Ver: helpers.ProtocolVersion, IdempotencyKey: idem, Requester: requester, Items: items,
	}
	req.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, req)
	return req
}

func awaitHook(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func executeUntilCanceled(
	t *testing.T, h *testHarness, req *rampv1.TransactionRequest, entered, forwarded <-chan struct{},
) {
	t.Helper()
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan error, 1)
	go func() {
		_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))
		done <- err
	}()
	awaitHook(t, entered, "billing hook entry")
	cancel()
	awaitHook(t, forwarded, "real billing call after cancellation")
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled original ExecuteTransaction succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled original ExecuteTransaction did not return")
	}
}

func TestLegacyNullClaim_ZeroRowsViaCancellationExecutesFresh(t *testing.T) {
	h, rec := newRecordingHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/legacy-null-cancel-zero", "50.00")
	offer := discoverOffer(t, h, uri)

	entered, forwarded := make(chan struct{}), make(chan struct{})
	rec.mu.Lock()
	rec.beforeAuthorize = func(ctx context.Context) { close(entered); <-ctx.Done() }
	rec.afterAuthorize = func(context.Context) { close(forwarded) }
	rec.mu.Unlock()

	const idem = "tx-legacy-null-cancel-zero"
	executeUntilCanceled(t, h, signedExecuteRequest(t, h, idem, offer), entered, forwarded)
	rec.mu.Lock()
	rec.beforeAuthorize, rec.afterAuthorize = nil, nil
	rec.mu.Unlock()
	assertNoTransaction(t, h, derivedTxKey(idem, offer))

	if err := h.billing.Credit(h.ctx, h.billingRef,
		mustBillingAmount(t, "100.00", "USD"), "topup-legacy-null-cancel-zero"); err != nil {
		t.Fatalf("credit top-up: %v", err)
	}
	retry, err := executeSingleItem(t, h, idem, offer)
	if err != nil {
		t.Fatalf("retry over a NULL claim with zero rows must execute fresh: %v", err)
	}
	if retry.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("fresh retry returned no retrieval endpoint")
	}
}

func TestLegacyNullClaim_CompleteRowsViaCancellationReconstructsWithoutRebilling(t *testing.T) {
	h, rec := newRecordingHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/legacy-null-cancel-complete", "0.05")
	offer := discoverOffer(t, h, uri)

	entered, forwarded := make(chan struct{}), make(chan struct{})
	rec.mu.Lock()
	rec.beforeRecord = func(ctx context.Context) { close(entered); <-ctx.Done() }
	rec.afterRecord = func(context.Context) { close(forwarded) }
	rec.mu.Unlock()

	const idem = "tx-legacy-null-cancel-complete"
	executeUntilCanceled(t, h, signedExecuteRequest(t, h, idem, offer), entered, forwarded)
	rec.mu.Lock()
	rec.beforeRecord, rec.afterRecord = nil, nil
	rec.mu.Unlock()

	committed, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(idem, offer))
	if err != nil {
		t.Fatalf("original committed row must exist: %v", err)
	}
	balAfterOriginal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after original: %v", err)
	}

	retry, err := executeSingleItem(t, h, idem, offer)
	if err != nil {
		t.Fatalf("retry over a NULL claim with complete rows must reconstruct: %v", err)
	}
	if got := retry.Msg.GetItems()[0].GetTransactionId(); got != committed.TransactionID {
		t.Fatalf("reconstructed transaction_id = %q, want %q", got, committed.TransactionID)
	}
	balAfterRetry, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after retry: %v", err)
	}
	if balAfterRetry.Value.Cmp(balAfterOriginal.Value) != 0 {
		t.Fatalf("balance moved on reconstructed retry: %s -> %s",
			balAfterOriginal.Value.FloatString(4), balAfterRetry.Value.FloatString(4))
	}
}

func TestLegacyNullClaim_PartialRowsViaCancellationRefusesSafely(t *testing.T) {
	h, rec := newRecordingHarness(t)
	direURI := seedResourceWithRate(t, h, "/articles/legacy-null-cancel-dire", "50.00")
	cheapURI := seedResourceWithRate(t, h, "/articles/legacy-null-cancel-cheap", "0.05")
	dire := discoverOffer(t, h, direURI)
	cheap := discoverOffer(t, h, cheapURI)

	entered, forwarded := make(chan struct{}), make(chan struct{})
	rec.mu.Lock()
	rec.beforeRecord = func(ctx context.Context) { close(entered); <-ctx.Done() }
	rec.afterRecord = func(context.Context) { close(forwarded) }
	rec.mu.Unlock()

	const idem = "tx-legacy-null-cancel-partial"
	// Denied first, successful second: cancellation at the successful Record
	// occurs after both item outcomes are known and exactly one row is durable.
	executeUntilCanceled(t, h, signedExecuteRequest(t, h, idem, dire, cheap), entered, forwarded)
	rec.mu.Lock()
	rec.beforeRecord, rec.afterRecord = nil, nil
	rec.mu.Unlock()
	balAfterOriginal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after original: %v", err)
	}

	_, err = h.exchangeClient.ExecuteTransaction(h.ctx,
		connect.NewRequest(signedExecuteRequest(t, h, idem, dire, cheap)))
	assertConnectCode(t, err, connect.CodeAlreadyExists)
	balAfterRetry, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after retry: %v", err)
	}
	if balAfterRetry.Value.Cmp(balAfterOriginal.Value) != 0 {
		t.Fatalf("balance moved on refused partial retry: %s -> %s",
			balAfterOriginal.Value.FloatString(4), balAfterRetry.Value.FloatString(4))
	}
}

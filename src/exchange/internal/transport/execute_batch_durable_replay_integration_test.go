//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"net/http"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// restartedExchangeClient stands up a SECOND Exchange server instance over the
// SAME testcontainers Postgres pool, billing adapter, keystore, and offer signer
// as h, but with a FRESH service.NewExchangeService that shares NO in-process
// state with the first server. This is the doctrine-approved restart simulation:
// a process that holds none of the first server's memory, replaying against an
// already-persisted transaction_log row. It proves the replay reconstruct path is
// purely DURABLE (it reads the original result back out of transaction_log), not
// dependent on any in-memory cache that a restart/failover would lose.
//
// It reuses h's pool/queries (same DB → the leg-1 row persists), h's billing
// inner adapter (same balance → a double charge is observable), h's offerSigner
// + keystore (so URL minting/well-known wiring matches), and the SAME caller
// identity (h.callerPub/callerPriv) registered with a fresh allowAllRegistry +
// allowAllManifestCache so the second server authenticates the same agent. The
// returned client signs with h.callerPriv, exactly like h.exchangeClient.
func restartedExchangeClient(t *testing.T, h *testHarness) rampconnect.ExchangeServiceClient {
	t.Helper()
	const callerID = "agent-test"
	registry := newAllowAllRegistry()
	registry.put(callerID, h.callerPub)
	manifests := newAllowAllManifestCache(callerID)

	srv := startExchangeServer(t, exchangeServerDeps{
		pool:        h.pool,
		queries:     h.queries,
		registry:    registry,
		manifests:   manifests,
		bill:        h.billing,
		signer:      h.offerSigner,
		keystore:    h.keystore,
		logger:      testutil.DiscardLogger(),
		httpsigKeys: map[string]ed25519.PublicKey{rwtestutil.MustThumbprintPriv(h.callerPriv): h.callerPub},
	})
	// A restarted Exchange rebuilds its in-memory catalog snapshot from the DB on
	// startup; mirror that so the second server can resolve the offer leg-1
	// persisted (otherwise discovery/redemption sees an empty snapshot and the
	// replay fails with not_found before reaching the durable replay path).
	if err := srv.catalogSvc.Bootstrap(h.ctx); err != nil {
		t.Fatalf("restart catalog bootstrap: %v", err)
	}

	signingClient := &http.Client{Transport: newSigningTransport(srv.baseTransport, callerID, h.callerPriv)}
	return rampconnect.NewExchangeServiceClient(signingClient, srv.server.URL, connect.WithGRPC())
}

// TestExecuteTransaction_DurableReplayAfterRestartReturnsOriginalResult exercises
// the DURABLE replay path, the one a same-process test cannot reach: leg 2 replays
// through a SECOND Exchange server that shares NO in-process state with the first,
// so the only way it can recognize the replay and return the original result is by
// reading it back out of the persisted transaction_log row.
//
// Core invariant: a duplicate idempotency_key returns the ORIGINAL
// TransactionResponse verbatim (same transaction_id, same retrieval_endpoint) as a
// SUCCESS — ramp.proto conformance ("a replay returns the original result rather
// than re-executing") — with NO second persisted row and NO double charge,
// reconstructed PURELY from the durable transaction_log row (incl. its serialized
// result_payload). This is the exact path that a reconstruct relying on an
// in-memory cache would break, which is why the restart shape is retained: it
// proves the reconstruct is durable.
//
// This supersedes the earlier interim contract (a replay surfaced as connect code
// AlreadyExists); the proto conformance requirement makes the replay return the
// original result instead of an error. The no-double-charge / no-double-persist
// invariants from the earlier test are preserved verbatim below.
//
// Round-trip honesty:
//   - leg-1 WRITE: agent → ExecuteTransaction RPC on server #1 (real Connect
//     HTTP) → transport → service → repo → DB. A full PROTOCOL+PERSISTENCE
//     round-trip.
//   - leg-2 REPLAY: agent → ExecuteTransaction RPC on server #2 (fresh process,
//     same DB) → durable replay reconstruct from transaction_log → original
//     result. A full PROTOCOL round-trip through the same RPC surface, exercising
//     the durable replay code that a same-process test never reaches cold.
//   - side-effect ABSENCE (no second row, charged exactly once): the no-row leg
//     is a PERSISTENCE check via the production repository surface
//     repo.TransactionRepo.ByIdempotencyKey (the documented tier-2 fallback —
//     there is no public transaction-read RPC),
//     plus the billing adapter's GetBalance. No raw sqlc / SQL / second DB
//     connection (Testing Doctrine §9). The persisted row lives under the
//     DERIVED key idempotency_key:offer_id (exchange_batch.go runBatchItemBilling),
//     so the lookup uses that derived key.
func TestExecuteTransaction_DurableReplayAfterRestartReturnsOriginalResult(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/durable-idem", "0.05")
	offer := discoverOffer(t, h, uri)

	const idem = "tx-durable-idem"
	requester := newRequester("agent-test", "agent.example")
	req := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, idem)},
		},
	}
	req.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, req)

	// Leg 1 (server #1): the original request succeeds — HTTP 200, one item, a
	// signed retrieval endpoint, no per-item denial. Persists the transaction_log
	// row under the derived key and debits 0.05 from the 10.00 seed → 9.95.
	resp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("first call must succeed: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 1 {
		t.Fatalf("first call returned %d items, want 1", len(items))
	}
	if items[0].GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED {
		t.Fatalf("first call item unexpectedly denied: %v", items[0].GetDenialReason())
	}
	origURL := items[0].GetRetrievalEndpoint()
	origTxID := items[0].GetTransactionId()
	if origURL == "" || origTxID == "" {
		t.Fatalf("first call missing retrieval_endpoint/transaction_id: url=%q tx=%q", origURL, origTxID)
	}

	derivedKey := idem + ":" + offer.GetOfferId()
	repoTx := repo.NewTransactionRepo(h.queries)
	if rec, rerr := repoTx.ByIdempotencyKey(ctx, derivedKey); rerr != nil {
		t.Fatalf("ByIdempotencyKey(derived %q) after first call = %v, want a persisted row", derivedKey, rerr)
	} else if rec.TransactionID == "" {
		t.Fatal("first-call persisted transaction has empty transaction_id")
	}
	balAfterFirst, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after first: %v", err)
	}
	if want := mustBillingAmount(t, "9.95", "USD"); balAfterFirst.Value.Cmp(want.Value) != 0 {
		t.Fatalf("balance after first call = %s, want 9.95 (one charge)", balAfterFirst.Value.FloatString(4))
	}

	// Restart: a SECOND Exchange server over the SAME pool/DB that shares no
	// in-process state with the first. The leg-1 row persists; the second server
	// holds nothing in memory, so it must reconstruct the original result purely
	// from the durable transaction_log row.
	restarted := restartedExchangeClient(t, h)

	// Leg 2 (server #2): REPLAY the SAME request. With no shared in-process state,
	// the second server reconstructs the original response from the persisted
	// transaction_log row (incl. result_payload) and returns it verbatim — same
	// transaction_id, same retrieval_endpoint — as a SUCCESS, not an error.
	second, replayErr := restarted.ExecuteTransaction(ctx, connect.NewRequest(req))
	if replayErr != nil {
		t.Fatalf("durable replay must return the original result, not an error: %v", replayErr)
	}
	replayItems := second.Msg.GetItems()
	if len(replayItems) != 1 {
		t.Fatalf("durable replay returned %d items, want 1 (the original)", len(replayItems))
	}
	if got := replayItems[0].GetTransactionId(); got != origTxID {
		t.Fatalf("durable replay transaction_id = %q, want the original %q", got, origTxID)
	}
	if got := replayItems[0].GetRetrievalEndpoint(); got != origURL {
		t.Fatalf("durable replay retrieval_endpoint = %q, want the ORIGINAL %q verbatim", got, origURL)
	}

	// The durable replay must not double-persist or double-charge: balance
	// unchanged at 9.95 (still exactly one charge), and the derived-key row is
	// still the lone persisted transaction.
	balAfterReplay, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after replay: %v", err)
	}
	if balAfterReplay.Value.Cmp(balAfterFirst.Value) != 0 {
		t.Fatalf("balance after durable replay = %s, want unchanged 9.95 (no double charge)",
			balAfterReplay.Value.FloatString(4))
	}
	if _, rerr := repoTx.ByIdempotencyKey(ctx, derivedKey); rerr != nil {
		t.Fatalf("ByIdempotencyKey(derived %q) after replay = %v, want the single persisted row to survive",
			derivedKey, rerr)
	}
}

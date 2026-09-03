//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// TestExecuteTransaction_ReplayReturnsOriginalResult pins the proto idempotency
// conformance requirement (ramp.proto TransactionRequest.idempotency_key, ~1677):
// "The server MUST dedupe on this: a replay returns the ORIGINAL result rather
// than re-executing."
//
// A replayed ExecuteTransaction (same idempotency_key + same request) MUST return
// the ORIGINAL TransactionResponse verbatim — the same transaction_id AND the same
// signed retrieval_endpoint — as a SUCCESS, and MUST NOT charge a second time. The
// chosen implementation persists the original response and returns it byte-for-byte
// on replay (no re-minting of a fresh signed URL, which would let a client
// mint→fetch→mint indefinitely for one charge); if the stored URL has since
// expired, that is the agent's problem (re-buy), not a re-issue.
//
// RED on HEAD: the request-level idempotency check (exchange_batch.go) and the
// durable transaction_log UNIQUE backstop (exchange.go) both surface a replay as
// KindIdempotent → connect.CodeAlreadyExists, so on HEAD `replayErr` is non-nil and
// `second` is nil — the success + original-result + same-URL assertions below all
// fail. This test drives the public ExecuteTransaction RPC for both legs and reads
// the result back through that same surface (no internal-state access); the
// no-double-charge assertion observes the production billing service.
func TestExecuteTransaction_ReplayReturnsOriginalResult(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/replay-conformance", "0.05")
	offer := discoverOffer(t, h, uri)

	const idem = "tx-replay-original"
	requester := newRequester("agent-test", "agent.example")
	req := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, idem)},
		},
	}

	// Leg 1: the original execute succeeds; capture the original result verbatim.
	first, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("first call must succeed: %v", err)
	}
	firstItems := first.Msg.GetItems()
	if len(firstItems) != 1 {
		t.Fatalf("first call returned %d items, want 1", len(firstItems))
	}
	origURL := firstItems[0].GetRetrievalEndpoint()
	origTxID := firstItems[0].GetTransactionId()
	if origURL == "" || origTxID == "" {
		t.Fatalf("first call missing retrieval_endpoint/transaction_id: url=%q tx=%q", origURL, origTxID)
	}
	balAfterFirst, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after first: %v", err)
	}

	// Leg 2: REPLAY the SAME request. Conformance: return the original result, not
	// an error, and do not re-execute (no second charge).
	second, replayErr := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))
	if replayErr != nil {
		t.Fatalf("replay must return the original result, not an error: %v", replayErr)
	}
	replayItems := second.Msg.GetItems()
	if len(replayItems) != 1 {
		t.Fatalf("replay returned %d items, want 1 (the original)", len(replayItems))
	}
	if got := replayItems[0].GetTransactionId(); got != origTxID {
		t.Fatalf("replay transaction_id = %q, want the original %q", got, origTxID)
	}
	if got := replayItems[0].GetRetrievalEndpoint(); got != origURL {
		t.Fatalf("replay retrieval_endpoint = %q, want the ORIGINAL %q verbatim (not a freshly minted URL)", got, origURL)
	}

	// No second charge: balance unchanged from after the first call.
	balAfterReplay, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after replay: %v", err)
	}
	if balAfterReplay.Value.Cmp(balAfterFirst.Value) != 0 {
		t.Fatalf("balance after replay = %s, want unchanged %s (no double charge)",
			balAfterReplay.Value.FloatString(4), balAfterFirst.Value.FloatString(4))
	}
}

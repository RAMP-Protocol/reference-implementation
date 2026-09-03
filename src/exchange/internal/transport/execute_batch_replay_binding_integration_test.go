//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Request-level possession binding across admission and both replay paths.
//
// Admission proves possession by scanning EVERY item for one verifiable body
// acceptance; the replay serve paths must reuse THAT binding, not re-derive one
// from items[0]. Before the fix the two disagreed: an invalid-first/valid-second
// batch passed admission on item 1, executed, and finalized, but its exact retry
// re-derived possession from items[0] (invalid) and failed signature_invalid
// instead of replaying the stored response.
//
// Round-trip honesty: every leg drives the public ExecuteTransaction RPC and
// asserts through the response; the stored response is observed by replaying it,
// never by reading persistence directly.

// TestExecuteBatch_InvalidFirstValidSecond_ReplaysFinalizedResponse pins the
// request-level binding fix: a 2-item batch whose FIRST item's acceptance is
// signed with the wrong key (invalid) and whose SECOND is valid succeeds on the
// second item and finalizes a response; the exact retry replays that finalized
// response verbatim (same transaction_id on item 1, same in-body denial on item
// 0), never a top-level signature_invalid from re-checking item 0.
func TestExecuteBatch_InvalidFirstValidSecond_ReplaysFinalizedResponse(t *testing.T) {
	h := newTestHarness(t)
	uriA := seedResourceWithRate(t, h, "/articles/binding-invalid-first", "0.05")
	uriB := seedResourceWithRate(t, h, "/articles/binding-valid-second", "0.05")
	offerA := discoverOffer(t, h, uriA)
	offerB := discoverOffer(t, h, uriB)

	// A key the agents row does NOT hold: acceptances signed with it never verify
	// against agent-test's registered key, so item 0 is denied SIGNATURE_INVALID.
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("wrong-key ed25519: %v", err)
	}

	const idem = "tx-binding-invalid-first"
	requester := newRequester("agent-test", "agent.example")
	build := func() *connect.Request[rampv1.TransactionRequest] {
		req := &rampv1.TransactionRequest{
			Ver:            helpers.ProtocolVersion,
			IdempotencyKey: idem,
			Requester:      requester,
			Items: []*rampv1.TransactionItem{
				{Offer: offerA, AgentAcceptance: signAcceptanceFor(t, wrongPriv, offerA, requester, idem)},
				{Offer: offerB, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offerB, requester, idem)},
			},
		}
		req.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, req)
		return connect.NewRequest(req)
	}

	// Original: item 0 denied in-body, item 1 succeeds and the response finalizes.
	first, err := h.exchangeClient.ExecuteTransaction(h.ctx, build())
	if err != nil {
		t.Fatalf("original invalid-first/valid-second batch must succeed at the request level: %v", err)
	}
	firstItems := first.Msg.GetItems()
	if len(firstItems) != 2 {
		t.Fatalf("original response carried %d items, want 2", len(firstItems))
	}
	if got := firstItems[0].GetDenialReason(); got != rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID {
		t.Fatalf("item 0 denial_reason = %v, want SIGNATURE_INVALID", got)
	}
	if firstItems[1].GetRetrievalEndpoint() == "" {
		t.Fatal("item 1 (valid) carried no retrieval endpoint on the original")
	}
	wantTxID := firstItems[1].GetTransactionId()

	// Exact retry: must REPLAY the finalized response verbatim, not re-check item 0.
	second, err := h.exchangeClient.ExecuteTransaction(h.ctx, build())
	if err != nil {
		t.Fatalf("exact retry must replay the finalized response, not fail: %v", err)
	}
	secondItems := second.Msg.GetItems()
	if len(secondItems) != 2 {
		t.Fatalf("retry response carried %d items, want 2", len(secondItems))
	}
	if got := secondItems[1].GetTransactionId(); got != wantTxID {
		t.Fatalf("retry item 1 transaction_id = %q, want the finalized %q — re-executed instead of replayed",
			got, wantTxID)
	}
	if got := secondItems[0].GetDenialReason(); got != rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID {
		t.Fatalf("retry item 0 denial_reason = %v, want the replayed SIGNATURE_INVALID", got)
	}
}

// TestExecuteBatch_NoVerifiableItem_LeavesNoClaim pins the other half of the
// binding fix: a batch in which NO item's acceptance verifies proves no
// possession, so it creates no claim. The agent's OWN later request under the
// same idempotency_key with a DIFFERENT item set therefore proceeds as fresh — a
// reserved claim would have refused it AlreadyExists (KindIdempotent).
func TestExecuteBatch_NoVerifiableItem_LeavesNoClaim(t *testing.T) {
	h := newTestHarness(t)
	uriA := seedResourceWithRate(t, h, "/articles/no-verifiable-a", "0.05")
	uriB := seedResourceWithRate(t, h, "/articles/no-verifiable-b", "0.05")
	offerA := discoverOffer(t, h, uriA)
	offerB := discoverOffer(t, h, uriB)

	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("wrong-key ed25519: %v", err)
	}

	const idem = "tx-no-verifiable-item"
	requester := newRequester("agent-test", "agent.example")
	// Every item signed with the wrong key: none verifies, so possession is not
	// proven and no claim is reserved.
	unproven, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offerA, AgentAcceptance: signAcceptanceFor(t, wrongPriv, offerA, requester, idem)},
		},
	}))
	if err != nil {
		t.Fatalf("all-unverifiable batch must surface denials in-body, not a connect error: %v", err)
	}
	if got := unproven.Msg.GetItems()[0].GetDenialReason(); got != rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID {
		t.Fatalf("unproven item denial_reason = %v, want SIGNATURE_INVALID", got)
	}

	// The agent's own later request under the SAME key with a DIFFERENT offer must
	// be fresh — a reserved claim (with the first item set's digest) would refuse
	// this as AlreadyExists.
	fresh, err := executeSingleItem(t, h, idem, offerB)
	if err != nil {
		t.Fatalf("later same-key request with a different item set must be fresh, not AlreadyExists: %v", err)
	}
	if fresh.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("fresh later request returned no retrieval endpoint — the unproven batch wrongly reserved a claim")
	}
}

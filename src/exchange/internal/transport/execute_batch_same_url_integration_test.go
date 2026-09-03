//go:build integration

package transport_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestExecuteTransaction_TwoOffersForSameURLInOneBatch pins the batch contract
// that motivated the random per-offer offer_id: two SEPARATELY DISCOVERED
// offers for the SAME URL execute in one batch and produce two correctly
// correlated results, two transaction rows, and distinct transaction ids.
// Before the mint, both offers carried the resource-derived id, so results
// keyed by offer_id collapsed and the second item died on the derived replay
// key — correlating batch results by offer_id is now correct, which is what
// makes a position-based merge workaround unnecessary downstream.
func TestExecuteTransaction_TwoOffersForSameURLInOneBatch(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)

	// Two separate discoveries of the same URL: two issued offers, each with
	// its own offer_id.
	offerA := discoverFirst(t, h)[0]
	offerB := discoverFirst(t, h)[0]
	if offerA.GetOfferId() == offerB.GetOfferId() {
		t.Fatalf("premise broken: two discoveries share offer_id %q", offerA.GetOfferId())
	}

	const reqKey = "tx-two-offers-one-url"
	requester := agentRequester("agent-test")
	itemFor := func(o *rampv1.Offer) *rampv1.TransactionItem {
		return &rampv1.TransactionItem{
			Offer:           o,
			AgentAcceptance: signAcceptanceFor(t, h.callerPriv, o, requester, reqKey),
		}
	}
	resp, err := executeItems(t, h, reqKey, itemFor(offerA), itemFor(offerB))
	if err != nil {
		t.Fatalf("execute batch: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("result items = %d, want 2 (one per presented offer)", len(items))
	}

	// Correlation: each result carries the offer_id of the offer it answers,
	// and both presented offers are answered — nothing collapsed or duplicated.
	byOffer := map[string]*rampv1.TransactionResultItem{}
	for _, it := range items {
		if _, dup := byOffer[it.GetOfferId()]; dup {
			t.Fatalf("two result items carry offer_id %q — results collapsed", it.GetOfferId())
		}
		byOffer[it.GetOfferId()] = it
	}
	txRepo := repo.NewTransactionRepo(h.queries)
	txIDs := map[string]bool{}
	for _, o := range []*rampv1.Offer{offerA, offerB} {
		it, ok := byOffer[o.GetOfferId()]
		if !ok {
			t.Fatalf("no result item for presented offer %q", o.GetOfferId())
		}
		if it.GetDenialReason() != rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED {
			t.Fatalf("offer %q denied (%v), want success", o.GetOfferId(), it.GetDenialReason())
		}
		if it.GetRetrievalEndpoint() == "" {
			t.Errorf("offer %q result carries no retrieval_endpoint", o.GetOfferId())
		}
		txIDs[it.GetTransactionId()] = true

		// Its own transaction row exists and records THIS offer's identity.
		// Read via repo.TransactionRepo.ByID — the documented tier-2 surface
		// (Testing Doctrine pt9; no public agent-plane transaction-read RPC
		// yet), so this leg is a persistence read, not a protocol round-trip.
		rec, err := txRepo.ByID(h.ctx, it.GetTransactionId())
		if err != nil {
			t.Fatalf("TransactionRepo.ByID(%q): %v", it.GetTransactionId(), err)
		}
		if rec.OfferID != o.GetOfferId() {
			t.Errorf("row %q offer_id = %q, want %q", it.GetTransactionId(), rec.OfferID, o.GetOfferId())
		}
	}
	if len(txIDs) != 2 {
		t.Errorf("distinct transaction ids = %d, want 2", len(txIDs))
	}

	// Both purchases really billed: two 0.05 charges against the 10.00 seed.
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	want := mustBillingAmount(t, "9.90", "USD")
	if bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance after two purchases = %s, want %s", bal.Value.FloatString(2), want.Value.FloatString(2))
	}
}

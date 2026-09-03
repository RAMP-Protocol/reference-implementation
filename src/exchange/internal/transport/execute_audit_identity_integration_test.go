//go:build integration

package transport_test

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestExecuteTransaction_PersistsOfferAndResourceIdentityUnconflated pins the
// audit contract: the transaction log records BOTH identities of a purchase —
// the catalog resource that was delivered (resource_id) and the exact signed
// offer that was redeemed (offer_id) — without conflating them. offer_id is a
// random per-offer UUID, so the two values must differ, and the evidence row's
// offer_id must agree with the transaction log's.
//
// Round-trip honesty: the arrange side drives push -> discover -> execute
// through the public RPCs. The evidence read goes through the public admin
// evidence surface. The transaction_log read goes through repo.TransactionRepo
// .ByID — the documented tier-2 surface (Testing Doctrine pt9; no public
// agent-plane transaction-read RPC exists yet), so that leg is a persistence
// read, not a protocol round-trip.
func TestExecuteTransaction_PersistsOfferAndResourceIdentityUnconflated(t *testing.T) {
	h := newTestHarness(t)
	_, baseURL := startAdminServer(t, h, "127.0.0.0/8")
	seedCatalog(t, h)
	offer := discoverFirst(t, h)[0]

	resp, err := executeSingleItem(t, h, "tx-audit-ids", offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	item := singleResultItem(t, resp)
	txID := item.GetTransactionId()
	if txID == "" {
		t.Fatalf("execute was denied in-body (reason=%v); want success", item.GetDenialReason())
	}

	rec, err := repo.NewTransactionRepo(h.queries).ByID(h.ctx, txID)
	if err != nil {
		t.Fatalf("TransactionRepo.ByID(%q): %v", txID, err)
	}
	// offer_id is the presented signed offer's own id, verbatim.
	if got, want := rec.OfferID, offer.GetOfferId(); got != want {
		t.Errorf("transaction_log.offer_id = %q, want the presented signed offer id %q", got, want)
	}
	// resource_id is the resolved catalog entry: the tenant-scoped id derived
	// from the pushed entry (no content_id pushed, so the key is the URI).
	wantResource := h.tenantID + ":https://" + h.tenantDomain + "/articles/hello"
	if got := rec.ResourceID; got != wantResource {
		t.Errorf("transaction_log.resource_id = %q, want the catalog entry id %q", got, wantResource)
	}
	// The two identities are genuinely distinct values, not one written twice.
	if rec.ResourceID == rec.OfferID {
		t.Errorf("resource_id and offer_id are both %q — the two identities are conflated", rec.OfferID)
	}

	// The evidence row's offer identity agrees with the transaction log's.
	view := readEvidence(t, h, baseURL, txID)
	if got, want := view.Evidence.OfferID, rec.OfferID; got != want {
		t.Errorf("evidence offer_id = %q, want %q (must agree with transaction_log.offer_id)", got, want)
	}
}

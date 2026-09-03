//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// A resource that leaves the catalog after its offer was issued is a per-item
// DENIAL (DENIAL_REASON_CONTENT_UNAVAILABLE), not a batch abort.
//
// The distinction is about what the request claim ends up holding. Admission
// claims (agent, idempotency_key) before any item runs, and executeBatch stores
// the finalized response onto that claim only when the batch produces one. While
// a catalog miss aborted the batch, the claim survived with NO stored response:
// an exact retry lost the claim and waited out the finalization poll before
// failing the same way, and a corrected request carrying a newly issued offer was
// refused as a changed item set. Classifying the miss as a denial finalizes a
// complete response, so the retry replays it and the sibling items in the same
// batch still execute.
//
// Round-trip honesty: every leg drives the public ExecuteTransaction RPC. Billing
// effects are observed through the recording adapter and GetBalance, persistence
// absence through the production repository surface — never raw SQL.

// missingResourceOffer re-signs a genuine offer onto a canonical URL that names
// a path this Exchange never pushed, producing an authentically signed offer
// whose resource is not in the catalog. That is the shape an agent holds after
// the publisher withdraws content it had already been offered.
func missingResourceOffer(t *testing.T, h *testHarness, genuine *rampv1.Offer, path string) *rampv1.Offer {
	t.Helper()
	return resignedOffer(t, h, genuine, func(o *rampv1.Offer) {
		u := "https://" + h.tenantDomain + path
		o.Identity.CanonicalUrl = &u
	})
}

// TestExecuteTransaction_CatalogMissDeniesItemAndFinalizes drives a two-item
// batch where the first item's resource is in the catalog and the second item's
// is not. The good item must execute and the missing one must come back denied
// CONTENT_UNAVAILABLE in the same successful response. The request then proves
// the response was finalized onto the claim: an exact retry returns it verbatim
// with no further billing, and reusing the key with a newly issued offer is
// refused because that is a different request.
func TestExecuteTransaction_CatalogMissDeniesItemAndFinalizes(t *testing.T) {
	h, rec := newRecordingHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/content-present", "0.05")
	withdrawnURI := seedResourceWithRate(t, h, "/articles/content-second", "0.05")
	present := discoverOffer(t, h, uri)
	// A separately issued offer — its own offer_id, so the batch carries no
	// duplicate — re-signed onto a path this Exchange never pushed. That is the
	// offer an agent still holds after the publisher withdraws the content.
	missing := missingResourceOffer(t, h, discoverOffer(t, h, withdrawnURI), "/articles/content-withdrawn")

	const idem = "tx-content-unavailable"
	requester := agentRequester("agent-test")
	items := []*rampv1.TransactionItem{
		{Offer: present, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, present, requester, idem)},
		{Offer: missing, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, missing, requester, idem)},
	}

	resp, err := executeItems(t, h, idem, items...)
	if err != nil {
		t.Fatalf("a catalog miss must deny its own item, not abort the batch: %v", err)
	}
	got := resp.Msg.GetItems()
	if len(got) != 2 {
		t.Fatalf("response carried %d items, want 2 (both items produce a result)", len(got))
	}
	if got[0].GetRetrievalEndpoint() == "" {
		t.Error("the item whose resource is still in the catalog carries no retrieval endpoint")
	}
	if r := got[0].GetDenialReason(); r != rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED {
		t.Errorf("present item denial_reason = %v, want none", r)
	}
	if r := got[1].GetDenialReason(); r != rampv1.DenialReason_DENIAL_REASON_CONTENT_UNAVAILABLE {
		t.Errorf("withdrawn item denial_reason = %v, want CONTENT_UNAVAILABLE", r)
	}
	if ep := got[1].GetRetrievalEndpoint(); ep != "" {
		t.Errorf("denied item carries retrieval endpoint %q; nothing may be delivered for withdrawn content", ep)
	}

	// Exactly one item billed and persisted: the denied item never authorized a
	// hold and never wrote a row.
	if n := rec.recordCallCount(); n != 1 {
		t.Errorf("Record calls = %d, want 1 (only the present item settles a charge)", n)
	}
	assertNoTransaction(t, h, derivedTxKey(idem, missing))
	// Exactly one 0.05 charge landed against the 10.00 starting balance.
	assertBalanceThrough(t, h.ctx, h.billing, h.billingRef, "9.95")

	// The response was finalized onto the claim: an exact retry returns it
	// verbatim and bills nothing further. Asserting call counts rather than how
	// fast the retry answered keeps this independent of wall-clock timing.
	authorizeBefore := rec.authorizeCallCount()
	retry, err := executeItems(t, h, idem, items...)
	if err != nil {
		t.Fatalf("exact retry must replay the finalized response: %v", err)
	}
	if !proto.Equal(resp.Msg, retry.Msg) {
		t.Fatalf("retry response differs from the original:\n orig=%v\n retry=%v", resp.Msg, retry.Msg)
	}
	if n := rec.authorizeCallCount(); n != authorizeBefore {
		t.Errorf("Authorize calls = %d after the retry, want %d (a replay bills nothing)", n, authorizeBefore)
	}

	// Reusing the key with a newly issued offer is a different request: the agent
	// re-discovers, gets a fresh offer_id, and must use a fresh idempotency key.
	reissued := discoverOffer(t, h, uri)
	_, reuseErr := executeSingleItem(t, h, idem, reissued)
	assertConnectCode(t, reuseErr, connect.CodeAlreadyExists)
}

// TestExecuteTransaction_EmptyCanonicalURLLeavesNoClaim pins the pre-claim half
// of the same rule. An offer with no signed canonical_url binds to nothing and
// is malformed rather than denied, so it is rejected during envelope validation
// — before admission claims the idempotency key. The proof that no claim
// survived is the next request: the same agent, the same key, a different item
// set, accepted as fresh. A surviving claim would refuse it AlreadyExists.
func TestExecuteTransaction_EmptyCanonicalURLLeavesNoClaim(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/canon-no-claim", "0.05")
	genuine := discoverOffer(t, h, uri)
	unbound := resignedOffer(t, h, genuine, func(o *rampv1.Offer) {
		o.Identity.CanonicalUrl = nil
	})

	const idem = "tx-canon-no-claim"
	_, err := executeSingleItem(t, h, idem, unbound)
	assertConnectError(t, err, connect.CodeInvalidArgument, "canonical_url")
	assertRejectionFieldInDomain(t, err, exchangeServiceDomainLiteral, "items.offer.identity.canonical_url")
	assertRejectionMeta(t, err, "item_index", "0")

	// The corrected request carries a NEWLY ISSUED offer, which is what an agent
	// actually retries with after re-discovering: a fresh offer_id, so a different
	// item set. If the malformed request had claimed the key, this would be
	// refused AlreadyExists for naming a different item set than the claim holds.
	reissued := discoverOffer(t, h, uri)
	if reissued.GetOfferId() == unbound.GetOfferId() {
		t.Fatal("re-discovery returned the same offer_id, so this leg would be an " +
			"exact retry and could not detect a stranded claim")
	}
	resp, err := executeSingleItem(t, h, idem, reissued)
	if err != nil {
		t.Fatalf("a request rejected before the claim must leave the key usable, got: %v", err)
	}
	if resp.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("the corrected request returned no retrieval endpoint")
	}
	// Only the corrected request charged; the rejected one never reached billing.
	assertBalanceThrough(t, h.ctx, h.billing, h.billingRef, "9.95")
}

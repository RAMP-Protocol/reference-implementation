//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
)

// The relay gate must reach a tenant verdict for EVERY item of a relayed
// request. An item it cannot attribute to a tenant — the signature does not
// verify, or the signed canonical_url matches no catalog entry — cannot be
// cleared, so the whole request is refused PermissionDenied.
//
// Skipping such an item was unsafe. On the replay path the disclosure comes from
// the STORED response, not from re-resolving the offer: a broker presenting an
// unresolvable body under an agent's existing key would find no tenant, pass a
// gate that had nothing left to check, and be served the stored signed URL. The
// sibling test file covers the same leak reached through an EXPIRED offer; here
// the offer never resolves at all.
//
// The fresh-request case below pins the behavior change that came with fail
// closed: a relayed batch used to deny the bad item in-body and execute its
// siblings, and now refuses the whole request before any of them runs.
//
// Round-trip honesty: every leg drives the public ExecuteTransaction RPC, over
// the real agent+broker multisig transport. Side effects are observed through the
// billing adapter and the production repository surface, never raw SQL.

// TestExecuteRelayReplay_UnresolvedOfferFailsClosed pins the replay path. An
// agent executes directly and finalizes a response holding a live signed URL. A
// broker then replays the SAME offer_id — so the item-set digest still matches
// the agent's claim — but presents an offer re-signed onto a canonical URL that
// is not in the catalog. The gate cannot name a tenant for that item, so it must
// refuse rather than skip the item and serve the stored URL.
func TestExecuteRelayReplay_UnresolvedOfferFailsClosed(t *testing.T) {
	h := newTestHarness(t)
	// allow_broker_relay defaults to FALSE, but that is not what this test turns
	// on: the item never reaches a tenant, so the opt-out is never consulted.
	uri := seedResourceWithRate(t, h, "/articles/relay-unresolved", "0.05")
	offer := discoverOffer(t, h, uri)

	const idem = "tx-relay-unresolved"
	original, err := executeSingleItem(t, h, idem, offer)
	if err != nil {
		t.Fatalf("agent-direct original must succeed: %v", err)
	}
	if original.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("original response carries no retrieval endpoint")
	}

	// Same offer_id, so the claim's item-set digest matches; unknown
	// canonical_url, so the item resolves to no tenant.
	unresolvable := missingResourceOffer(t, h, offer, "/articles/relay-not-in-catalog")
	if unresolvable.GetOfferId() != offer.GetOfferId() {
		t.Fatal("the replay body must carry the original offer_id, or the refusal " +
			"could come from the changed-item-set check instead of the relay gate")
	}

	relayClient := h.brokerRelayClient(t, "broker.unresolved.v1")
	replay, replayErr := executeBrokerRelay(t, h, relayClient, idem, unresolvable)
	if replayErr == nil {
		leaked := ""
		if items := replay.Msg.GetItems(); len(items) == 1 {
			leaked = items[0].GetRetrievalEndpoint()
		}
		t.Fatalf("SECURITY: an unresolvable relayed item was served the stored response "+
			"(leaked retrieval_endpoint=%q); want PermissionDenied", leaked)
	}
	assertConnectCode(t, replayErr, connect.CodePermissionDenied)

	// The refused relay changed nothing: no further charge, and the agent's own
	// exact retry still replays the ORIGINAL response off the untouched claim.
	assertBalanceThrough(t, h.ctx, h.billing, h.billingRef, "9.95")
	retry, err := executeSingleItem(t, h, idem, offer)
	if err != nil {
		t.Fatalf("the agent's exact retry must still replay the original: %v", err)
	}
	if !proto.Equal(original.Msg, retry.Msg) {
		t.Fatalf("the refused relay disturbed the stored response:\n orig=%v\n retry=%v",
			original.Msg, retry.Msg)
	}
}

// TestExecuteRelayFresh_UnresolvedItemRefusesWholeBatch pins the same arm on a
// FIRST execution, where there is no stored response to protect and the rule is
// all-or-nothing admission.
//
// The tenant that owns the resolvable item has allow_broker_relay=TRUE, so the
// ordinary relay opt-out cannot produce the refusal. The resolvable item is sent
// FIRST: the gate clears it against that tenant, then reaches the second item,
// which resolves to no tenant at all. Only the unresolved arm can refuse this
// request, and it must refuse the whole of it — the resolvable item does not
// execute.
func TestExecuteRelayFresh_UnresolvedItemRefusesWholeBatch(t *testing.T) {
	h := newTestHarness(t)
	h.enableBrokerRelay(t, h.tenantID)
	resolvableURI := seedResourceWithRate(t, h, "/articles/relay-fresh-ok", "0.05")
	otherURI := seedResourceWithRate(t, h, "/articles/relay-fresh-other", "0.05")
	resolvable := discoverOffer(t, h, resolvableURI)
	// A distinct offer (its own offer_id) re-signed onto a path never pushed, so
	// the batch carries no duplicate offer_id and the second item resolves to
	// nothing.
	unresolvable := missingResourceOffer(t, h, discoverOffer(t, h, otherURI), "/articles/relay-fresh-gone")

	const idem = "tx-relay-fresh-unresolved"
	relayClient := h.brokerRelayClient(t, "broker.fresh-unresolved.v1")
	_, err := executeBrokerRelayOffers(t, h, relayClient, idem, resolvable, unresolvable)
	assertConnectCode(t, err, connect.CodePermissionDenied)

	// All-or-nothing: the resolvable item, which cleared relay authorization,
	// still did not execute.
	assertNoTransaction(t, h, derivedTxKey(idem, resolvable))
	assertNoTransaction(t, h, derivedTxKey(idem, unresolvable))
	assertBalanceUnchanged(t, h)

	// And the refusal reserved no claim: the agent's own direct request under the
	// same key with a different item set proceeds as fresh. A reserved claim would
	// refuse it AlreadyExists.
	resp, err := executeSingleItem(t, h, idem, resolvable)
	if err != nil {
		t.Fatalf("a refused relay must reserve no claim, got: %v", err)
	}
	if resp.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Fatal("the agent-direct request after the refused relay returned no retrieval endpoint")
	}
}

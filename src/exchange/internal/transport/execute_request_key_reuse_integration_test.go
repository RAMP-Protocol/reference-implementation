//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Request-level idempotency across re-discovered offers.
//
// offer_id is a random per-offer UUID, so a caller that reuses one request
// idempotency_key with a NEWLY DISCOVERED offer for the same URL produces
// derived per-item keys (idempotency_key:offer_id) that miss every persisted
// row. Without a request-level claim, billing and persistence would simply run
// again under the same request key. These tests pin the claim: the key is
// bound to the item set it was first used with by the authenticated agent, an
// exact retry replays the original (execute_replay_conformance covers that
// leg), a reuse with different items is refused before side effects, and a
// DIFFERENT agent may use the same key independently.
//
// Round-trip honesty: every leg drives the public RPCs (PushResources →
// DiscoverResources → ExecuteTransaction). Side-effect absence is observed
// through the production repo.TransactionRepo (documented tier-2 fallback — no
// public transaction-read RPC exists yet) and the billing adapter's GetBalance.

// TestExecuteTransaction_RequestKeyReuseWithNewOfferRefused drives the
// double-charge scenario the claim closes: execute offer 1 under key K, then
// re-discover the same URL (a fresh random offer_id) and execute the new offer
// under the SAME key K as the SAME agent. The second request must be refused
// with AlreadyExists before any side effect — no second charge, no second row.
func TestExecuteTransaction_RequestKeyReuseWithNewOfferRefused(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/key-reuse", "0.05")

	const idem = "tx-key-reuse"
	first := discoverOffer(t, h, uri)
	if _, err := executeSingleItem(t, h, idem, first); err != nil {
		t.Fatalf("original execute must succeed: %v", err)
	}
	balAfterFirst, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after first: %v", err)
	}

	// Re-discover: same resource, fresh random offer_id.
	second := discoverOffer(t, h, uri)
	if second.GetOfferId() == first.GetOfferId() {
		t.Fatal("re-discovery returned the same offer_id; cannot exercise the reuse path")
	}

	_, reuseErr := executeSingleItem(t, h, idem, second)
	assertConnectError(t, reuseErr, connect.CodeAlreadyExists, "different item set")

	// No side effects from the refused reuse: no row under the new offer's
	// derived key, and the balance still reflects exactly one charge.
	assertNoTransaction(t, h, derivedTxKey(idem, second))
	balAfterReuse, err := h.billing.GetBalance(ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance after refused reuse: %v", err)
	}
	if balAfterReuse.Value.Cmp(balAfterFirst.Value) != 0 {
		t.Fatalf("balance moved on refused key reuse: %s -> %s (double charge)",
			balAfterFirst.Value.FloatString(4), balAfterReuse.Value.FloatString(4))
	}
}

// TestExecuteTransaction_RequestKeyIndependentPerAgent pins the scope of the
// claim: the claim row is keyed by (AUTHENTICATED agent, idempotency_key), so a
// different agent using the same key value with ITS OWN offers claims and
// executes independently — it is neither refused nor served agent A's stored
// result. Both agents send a complete-set request proof, which is what puts
// them both on the claim path: a request without one takes the compatibility
// branch and never calls ClaimRequest, so it would succeed here no matter how
// the claim were keyed and prove nothing.
//
// Keying the claim on idempotency_key alone turns this RED. Agent B would find
// agent A's stored digest under the shared key value, see a different item set,
// and be refused before executing.
//
// The qualifier is deliberate: presenting another agent's exact (key, offer)
// pair still lands on that agent's globally-keyed rows and is refused by the
// replay ownership gate (an intentional v1 limitation, pinned by the
// foreign-caller replay test). The resource is free so the second agent needs no
// billing account; the property under test is the claim's key scope, not billing.
func TestExecuteTransaction_RequestKeyIndependentPerAgent(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	uri := seedResourceWithRate(t, h, "/articles/key-per-agent", "0")

	const idem = "tx-key-shared-value"

	// Agent A (harness default caller) uses the key first. executeSingleItem
	// signs the complete-set proof, so A claims the key for its own item set.
	offerA := discoverOffer(t, h, uri)
	if _, err := executeSingleItem(t, h, idem, offerA); err != nil {
		t.Fatalf("agent A execute must succeed: %v", err)
	}

	// Agent B: its own registered key, its own freshly discovered offers, the
	// SAME idempotency_key value, and its own complete-set proof over each.
	clientB, _, bPriv := h.addCallerWithKey(t, "agent-b-key-scope", "AGENT")
	bRequester := newRequester("agent-b-key-scope", "agent-b.example")
	executeAsB := func(offer *rampv1.Offer) (*connect.Response[rampv1.TransactionResponse], error) {
		req := &rampv1.TransactionRequest{
			Ver:            helpers.ProtocolVersion,
			IdempotencyKey: idem,
			Requester:      bRequester,
			Items: []*rampv1.TransactionItem{
				{Offer: offer, AgentAcceptance: signAcceptanceFor(t, bPriv, offer, bRequester, idem)},
			},
		}
		req.AgentRequestAcceptance = signRequestAcceptanceFor(t, bPriv, req)
		return clientB.ExecuteTransaction(ctx, connect.NewRequest(req))
	}

	bResp, err := executeAsB(discoverOffer(t, h, uri))
	if err != nil {
		t.Fatalf("agent B with the same key value must execute independently: %v", err)
	}
	items := bResp.Msg.GetItems()
	if len(items) != 1 || items[0].GetTransactionId() == "" {
		t.Fatalf("agent B result malformed: %+v", items)
	}

	// B ended up holding a claim of its own, not sharing A's. Re-discovering the
	// resource yields a fresh random offer_id, so the derived per-item key of the
	// next request matches no persisted row; only a request-level claim under B's
	// own identity can refuse it. A B that never claimed would execute again here.
	_, reuseErr := executeAsB(discoverOffer(t, h, uri))
	assertConnectError(t, reuseErr, connect.CodeAlreadyExists, "different item set")
}

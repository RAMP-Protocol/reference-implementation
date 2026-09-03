//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// The accept side of the complete-set projection rule.
//
// An agent signs ONE proof over the whole ordered request set before any
// fan-out. A Broker then splits that set by offer.exchange, so each Exchange
// receives a STRICT SUBSET of the signed items together with the whole proof.
// That is the shape the rule is built for: the verifier filters the signed set
// down to the items naming ITSELF and requires the arriving items to equal that
// filtered list, in the signed order.
//
// The sibling test in this package pins the refusal for a subset that is short
// of what the signed set addressed to this Exchange. Both cases are subsets of
// the whole set, and only one is legitimate, so the accept side needs its own
// coverage — without it, "reject a subset" reads as the whole rule and a fix
// that refused honest fan-out traffic would look correct.

// TestExecuteTransaction_FanOutProjectionIsAccepted drives the projection a
// Broker sends when a batch spans two Exchanges: this Exchange's item alone,
// carrying the proof the agent signed over both. It must execute, and it must
// execute on the CLAIM path — an Exchange that quietly ignored the proof would
// also return success here, so the second leg separates the two.
func TestExecuteTransaction_FanOutProjectionIsAccepted(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/fanout-projection", "0.05")

	const idem = "tx-fanout-projection"
	requester := newRequester("agent-test", "agent.example")
	mine := discoverOffer(t, h, uri)
	mineItem := &rampv1.TransactionItem{
		Offer:           mine,
		AgentAcceptance: signAcceptanceFor(t, h.callerPriv, mine, requester, idem),
	}
	// The item the agent signed for a DIFFERENT Exchange. It never reaches this
	// one: only its offer signature and exchange name ride inside the signed
	// payload, which is all the projection rule compares against.
	sibling := &rampv1.TransactionItem{
		Offer: &rampv1.Offer{
			OfferId:   "offer-other-exchange",
			Exchange:  "other.exchange.example",
			Signature: "00112233445566778899aabbccddeeff",
		},
	}

	// What the agent signs, before the Broker splits anything.
	proof := signRequestAcceptanceFor(t, h.callerPriv, &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items:          []*rampv1.TransactionItem{mineItem, sibling},
	})

	// What the Broker sends here: our item only, the whole proof unchanged.
	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:                    helpers.ProtocolVersion,
		IdempotencyKey:         idem,
		Requester:              requester,
		Items:                  []*rampv1.TransactionItem{mineItem},
		AgentRequestAcceptance: proof,
	}))
	if err != nil {
		t.Fatalf("a fan-out projection carrying the complete-set proof must be accepted: %v", err)
	}
	if got := itemSignedURL(t, resp); got == "" {
		t.Fatal("projected item carries no retrieval endpoint")
	}

	// The proof was accepted, not ignored: this request holds the claim.
	//
	// The second request re-discovers the resource, so its offer_id is a fresh
	// random value and its derived per-item key matches no persisted row. It
	// carries its OWN valid proof over its own two-exchange set, so it passes
	// projection verification and reaches ClaimRequest — which is the point.
	// Only the request-level claim can refuse it there, on the stored digest of
	// the first item set. Reusing the FIRST proof instead would be refused one
	// step earlier, by projection verification, and would prove nothing about
	// the claim.
	reOffer := discoverOffer(t, h, uri)
	reItem := &rampv1.TransactionItem{
		Offer:           reOffer,
		AgentAcceptance: signAcceptanceFor(t, h.callerPriv, reOffer, requester, idem),
	}
	reProof := signRequestAcceptanceFor(t, h.callerPriv, &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items:          []*rampv1.TransactionItem{reItem, sibling},
	})
	_, reuseErr := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:                    helpers.ProtocolVersion,
		IdempotencyKey:         idem,
		Requester:              requester,
		Items:                  []*rampv1.TransactionItem{reItem},
		AgentRequestAcceptance: reProof,
	}))
	assertConnectError(t, reuseErr, connect.CodeAlreadyExists, "different item set")
}

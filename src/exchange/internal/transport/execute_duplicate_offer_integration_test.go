//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestExecuteTransaction_DuplicateOfferIDsRejected pins the duplicate-offer
// envelope guard: presenting the SAME offer_id on two items of one
// TransactionRequest is invalid and rejected during request validation with
// InvalidArgument (an envelope error, not an in-body denial), before billing
// or persistence. To buy the same resource twice, an agent obtains two
// separately issued offers.
//
// Why upfront rejection matters: items execute sequentially, so without this
// guard the first duplicate can complete before the second reaches the same
// derived transaction key (idempotency_key + offer_id) and fails persistence —
// after already performing authorization and URL signing. The zero-side-effect
// assertions below are the point of the guard: NO billing call of any kind
// (Authorize, Record, or Release, observed on the recording adapter) and no
// transaction row written.
func TestExecuteTransaction_DuplicateOfferIDsRejected(t *testing.T) {
	h, rec := newRecordingHarnessWith(t, harnessOptions{})
	seedCatalog(t, h)
	offer := discoverFirst(t, h)[0]

	const reqKey = "tx-dup-offer"
	requester := agentRequester("agent-test")
	item := &rampv1.TransactionItem{
		Offer:           offer,
		AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, reqKey),
	}
	// The same signed offer presented on two items — identical offer_id.
	_, err := executeItems(t, h, reqKey, item, item)
	assertConnectError(t, err, connect.CodeInvalidArgument, "duplicate offer_id")
	// The rejection is machine-readable, not just a sentence: the ErrorDetail
	// names the offending field and the index of the LATER duplicate, the same
	// two values the Broker's ingress copy of this rule returns. A client that
	// reaches the Exchange directly and a client that goes through a Broker read
	// the same diagnostics for the same malformed body.
	assertRejectionFieldInDomain(t, err, exchangeServiceDomainLiteral, "items.offer.offer_id")
	assertRejectionMeta(t, err, "item_index", "1")

	// Zero side effects: no billing lifecycle call ran and nothing persisted.
	assertBillingLifecycle(t, rec, false, 0, 0)
	assertNoTransaction(t, h, derivedTxKey(reqKey, offer))
	assertBalanceUnchanged(t, h)
}

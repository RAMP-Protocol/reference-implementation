//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
)

// TestExecuteTransaction_OneItemNamesAnotherExchange_RefusesTheWholeRequest
// pins the shape of the refusal on the message whose audience is stated per
// item, and the decision that goes with it: the request is refused whole, not
// denied item by item. The protocol's rule is about who a request is for, and a
// request half meant for us is not a request we act on in part.
//
// The refusal must reach the caller in the Broker's vocabulary. The Broker
// refuses the same field on the same message one hop away, reporting
// "offer.exchange" with the position in "item_index"; a second spelling here
// would make a client handle one class of fault twice. The position matters on
// its own — a caller with a twenty-item batch otherwise learns only that
// something in it named somebody else.
func TestExecuteTransaction_OneItemNamesAnotherExchange_RefusesTheWholeRequest(t *testing.T) {
	h := newTestHarness(t)
	offerOne, offerTwo := seedTwoResources(t, h)

	// The second item is addressed elsewhere. The offer's own signature no longer
	// covers this value, which does not matter and is the point: the recipient is
	// answered before the handler runs, so nothing about the offer has been read
	// when the request is refused.
	misaddressed, ok := proto.Clone(offerTwo).(*rampv1.Offer)
	if !ok {
		t.Fatal("clone offer")
	}
	misaddressed.Exchange = "other-exchange.example"

	const idem = "tx-recipient-mismatch"
	requester := newRequester("agent-test", "agent.example")
	_, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offerOne, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offerOne, requester, idem)},
			{
				Offer:           misaddressed,
				AgentAcceptance: signAcceptanceFor(t, h.callerPriv, misaddressed, requester, idem),
			},
		},
	}))

	assertConnectError(t, err, connect.CodeInvalidArgument, "addressed to a different Exchange")
	assertRecipientRefusal(t, err, "mismatch")
	assertReportRejectionField(t, err, "offer.exchange")
	assertRefusedItemIndex(t, err, "1")
	assertErrorDomain(t, err, exchangeServiceDomainLiteral)

	// The first item was addressed correctly and still must not execute: whole
	// request, whole refusal.
	assertNoTransaction(t, h, idem)
	assertBalanceUnchanged(t, h)
}

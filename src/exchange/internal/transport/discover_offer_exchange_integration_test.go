//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
)

// TestDiscover_OfferCarriesSignedExchangeDomain pins step 1 of the signed-exchange-domain routing contract: the
// Exchange populates Offer.exchange with its configured canonical domain BEFORE
// signing, so the field falls inside the signed offer payload
// (helpers.canonicalOfferPayload covers the whole Offer minus
// signature/signature_algorithm). The broker derives the execute-routing target
// from this signed field, retiring the X-RAMP-Exchange-Endpoint header.
//
// Round-trip: the offer is produced and read through the public
// CatalogService.PushResources → ExchangeService.DiscoverResources surface; the
// signature is then validated through the public ExecuteTransaction surface
// (which runs helpers.VerifyPresentedOffer against the presented bytes),
// proving the signature now covers offer.exchange. No raw DB / sqlc access.
func TestDiscover_OfferCarriesSignedExchangeDomain(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/exch-domain", "0.05")

	offer := discoverOffer(t, h, uri)

	// The configured canonical domain wired in startExchangeServer
	// (ExchangeConfig{Exchange: "exchange.ramp.test"}).
	const wantDomain = "exchange.ramp.test"
	if got := offer.GetExchange(); got != wantDomain {
		t.Fatalf("offer.exchange = %q, want %q", got, wantDomain)
	}
	if offer.GetSignature() == "" || offer.GetSignatureAlgorithm() != "EdDSA" {
		t.Fatalf("offer not signed: %+v", offer)
	}

	// VerifyPresentedOffer still passes: the genuine offer (carrying
	// offer.exchange) is accepted by ExecuteTransaction, which verifies the
	// presented signature server-side.
	const txID = "tx-exch-domain-ok"
	if _, err := executeSingleItem(t, h, txID, offer); err != nil {
		t.Fatalf("execute genuine offer with exchange field: %v", err)
	}
	// The items[] path persists under the DERIVED key idempotency_key:offer_id.
	assertTransactionLogged(t, h.ctx, h, derivedTxKey(txID, offer))
}

// TestDiscover_RepointedExchangeDomainRefusedBeforeTheHandler covers the
// attacker's obvious move: take a genuine offer and repoint its routing target
// at an Exchange of their choosing.
//
// It is refused before the handler runs, by the recipient check, because every
// item's offer.exchange has to name the Exchange receiving the request. That is
// a whole-request refusal rather than a per-item denial: the protocol's rule is
// about who the request is FOR, and a request meant for somebody else is not one
// this Exchange answers item by item. Nothing is persisted.
func TestDiscover_RepointedExchangeDomainRefusedBeforeTheHandler(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/exch-repointed", "0.05")
	offer := discoverOffer(t, h, uri)

	repointed, ok := proto.Clone(offer).(*rampv1.Offer)
	if !ok {
		t.Fatal("clone offer")
	}
	repointed.Exchange = "evil.exchange.test"

	const txID = "tx-exch-repointed"
	_, err := executeSingleItem(t, h, txID, repointed)
	assertConnectError(t, err, connect.CodeInvalidArgument, "addressed to a different Exchange")
	assertNoTransaction(t, h, derivedTxKey(txID, repointed))
}

// TestDiscover_TamperedExchangeDomainRejected proves offer.exchange is covered
// by the signature: mutating it after signing makes the presented bytes diverge
// from what the Exchange signed, so ExecuteTransaction's VerifyPresentedOffer
// rejects the offer with SIGNATURE_INVALID and persists no transaction. This is
// the security guarantee that lets the broker route from the signed field — a
// rogue caller cannot rewrite the routing target without breaking the signature.
//
// The tampered value is this Exchange's own domain with port 443 written out.
// That is deliberate, and it is what makes this test reach the signature at all:
// 443 is the default port a bare domain implies, so the recipient check folds it
// and the request is admitted as correctly addressed. The BYTES still differ from
// what was signed. So the case pins two things at once — that the field is inside
// the signature, and that the port folding the recipient check performs is not a
// way to edit a signed offer unnoticed.
func TestDiscover_TamperedExchangeDomainRejected(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/exch-tamper", "0.05")
	offer := discoverOffer(t, h, uri)

	tampered, ok := proto.Clone(offer).(*rampv1.Offer)
	if !ok {
		t.Fatal("clone offer")
	}
	tampered.Exchange = harnessExchangeDomain + ":443"

	const txID = "tx-exch-tampered"
	requester := newRequester("agent-test", "agent.example")
	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: txID,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{{
			Offer: tampered, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, tampered, requester, txID),
		}},
	}))
	// A tampered signed field → SIGNATURE_INVALID, a denial-map kind → in-body
	// per-item denial after the C4 items-only collapse (Flag #1).
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)
	assertNoTransaction(t, h, derivedTxKey(txID, tampered))
}

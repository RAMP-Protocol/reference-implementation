//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestExecuteRelay_ValidSubsetCannotClaimWholeRequestKey reproduces request-set
// poisoning by a broker that received an agent-signed two-item request but
// submits a one-item subset first while forwarding the original complete-set
// proof. The subset must be refused before it can claim the key.
func TestExecuteRelay_ValidSubsetCannotClaimWholeRequestKey(t *testing.T) {
	h := newTestHarness(t)
	h.enableBrokerRelay(t, h.tenantID)
	offerA := discoverOffer(t, h,
		seedResourceWithRate(t, h, "/articles/request-set-a", "0.05"))
	offerB := discoverOffer(t, h,
		seedResourceWithRate(t, h, "/articles/request-set-b", "0.05"))

	const idem = "tx-request-set-binding"
	requester := newRequester("agent-test", "agent.example")
	item := func(offer *rampv1.Offer) *rampv1.TransactionItem {
		return &rampv1.TransactionItem{
			Offer:           offer,
			AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, idem),
		}
	}

	intended := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items:          []*rampv1.TransactionItem{item(offerA), item(offerB)},
	}
	intended.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, intended)

	// A broker submits only A while forwarding the proof over A+B. Projection
	// verification detects the removal and leaves no claim behind.
	brokerClient := h.brokerOnlyClient(t, "broker.request-set.v1")
	if _, err := brokerClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:                    helpers.ProtocolVersion,
		IdempotencyKey:         idem,
		Requester:              requester,
		Items:                  []*rampv1.TransactionItem{item(offerA)},
		AgentRequestAcceptance: intended.GetAgentRequestAcceptance(),
	})); err == nil {
		t.Fatal("SECURITY: broker-submitted subset was accepted")
	}
	assertNoTransaction(t, h, derivedTxKey(idem, offerA))
	assertBalanceUnchanged(t, h)

	// The agent's intended A+B request remains usable under the same key.
	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(intended))
	if err != nil {
		t.Fatalf("SECURITY: broker-submitted subset consumed the intended request key: %v", err)
	}
	if len(resp.Msg.GetItems()) != 2 {
		t.Fatalf("intended response has %d items, want 2", len(resp.Msg.GetItems()))
	}
}

// poisonAttempt is one relay-poisoning scenario: two seeded offers, the shared
// envelope the agent signs over, and a broker-relayed request that preserves the
// agent's valid complete-set proof while replacing item B's own acceptance. Both
// tests below start from the same attempt and differ only in what they send
// afterwards under the same key.
type poisonAttempt struct {
	broker         rampconnect.ExchangeServiceClient
	requester      *rampv1.Requester
	idem           string
	offerA, offerB *rampv1.Offer
}

// refusePoisonAttempt seeds the scenario, sends the poisoned relay, and asserts
// it is refused with no side effect. It returns the pieces a follow-up request
// needs to reuse the same key.
func refusePoisonAttempt(t *testing.T, h *testHarness, slug, idem string) poisonAttempt {
	t.Helper()
	h.enableBrokerRelay(t, h.tenantID)
	offerA := discoverOffer(t, h,
		seedResourceWithRate(t, h, "/articles/"+slug+"-a", "0.05"))
	offerB := discoverOffer(t, h,
		seedResourceWithRate(t, h, "/articles/"+slug+"-b", "0.05"))
	requester := newRequester("agent-test", "agent.example")

	attack := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idem,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offerA, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offerA, requester, idem)},
			{
				Offer: offerB,
				AgentAcceptance: mintWrongKeyAcceptanceFor(
					t, offerB, requester, idem,
				),
			}, // broker replaced the agent's item-local acceptance
		},
	}
	attack.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, attack)

	brokerClient := h.brokerRelayClient(t, "broker."+slug+".v1")
	if _, err := brokerClient.ExecuteTransaction(h.ctx, connect.NewRequest(attack)); err == nil {
		t.Fatal("SECURITY: relayed request with an invalid item acceptance was accepted")
	} else {
		assertConnectCode(t, err, connect.CodeUnauthenticated)
	}
	assertNoTransaction(t, h, derivedTxKey(idem, offerA))
	assertNoTransaction(t, h, derivedTxKey(idem, offerB))
	assertBalanceUnchanged(t, h)

	return poisonAttempt{
		broker: brokerClient, requester: requester, idem: idem,
		offerA: offerA, offerB: offerB,
	}
}

// TestExecuteRelay_InvalidItemAcceptanceLeavesNoClaim proves the refused relay
// reserved nothing: the key is still free for a DIFFERENT item set.
//
// A one-item request over offer A alone signs a different complete-set proof, so
// its authenticated digest differs from the attack's. Had the attack left a claim
// behind, this request would be refused with AlreadyExists for using the key with
// a different item set. It executes instead, which is the public-RPC reading of
// "no claim survived" — no test needs to look at the claim row to see it.
func TestExecuteRelay_InvalidItemAcceptanceLeavesNoClaim(t *testing.T) {
	h := newTestHarness(t)
	a := refusePoisonAttempt(t, h, "request-item-proof-noclaim", "tx-request-item-proof-noclaim")

	different := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: a.idem,
		Requester:      a.requester,
		Items: []*rampv1.TransactionItem{
			{Offer: a.offerA, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, a.offerA, a.requester, a.idem)},
		},
	}
	different.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, different)

	resp, err := a.broker.ExecuteTransaction(h.ctx, connect.NewRequest(different))
	if err != nil {
		t.Fatalf("SECURITY: the refused attack reserved the key — a different item set "+
			"under it must still execute: %v", err)
	}
	if got := len(resp.Msg.GetItems()); got != 1 {
		t.Fatalf("response has %d items, want 1", got)
	}
	if resp.Msg.GetItems()[0].GetRetrievalEndpoint() == "" {
		t.Error("item carries no retrieval endpoint")
	}
	// Only the item that was actually sent executed.
	if _, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derivedTxKey(a.idem, a.offerA)); err != nil {
		t.Fatalf("offer A row must exist after the executed request: %v", err)
	}
	assertNoTransaction(t, h, derivedTxKey(a.idem, a.offerB))
}

// TestExecuteRelay_InvalidItemAcceptanceLeavesIntendedRequestExecutable proves
// the agent's own two-item request still goes through under the same key after
// the poisoned relay was refused, and that it does exactly what it should:
// both items succeed with signed URLs, both rows persist, and the balance moves
// by exactly the two items' cost.
//
// This request claims the key fresh — nothing reserved it earlier — so it is
// the fresh-claim path being exercised, not a recovery from a leftover claim.
func TestExecuteRelay_InvalidItemAcceptanceLeavesIntendedRequestExecutable(t *testing.T) {
	h := newTestHarness(t)
	a := refusePoisonAttempt(t, h, "request-item-proof", "tx-request-item-proof")

	intended := &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: a.idem,
		Requester:      a.requester,
		Items: []*rampv1.TransactionItem{
			{Offer: a.offerA, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, a.offerA, a.requester, a.idem)},
			{Offer: a.offerB, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, a.offerB, a.requester, a.idem)},
		},
	}
	intended.AgentRequestAcceptance = signRequestAcceptanceFor(t, h.callerPriv, intended)

	resp, err := a.broker.ExecuteTransaction(h.ctx, connect.NewRequest(intended))
	if err != nil {
		t.Fatalf("intended request after refused attack: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 2 {
		t.Fatalf("intended response has %d items, want 2", len(items))
	}
	for i, it := range items {
		if it.GetRetrievalEndpoint() == "" {
			t.Errorf("item[%d] (offer %q) carries no retrieval endpoint: %+v", i, it.GetOfferId(), it)
		}
	}
	txRepo := repo.NewTransactionRepo(h.queries)
	for _, offer := range []*rampv1.Offer{a.offerA, a.offerB} {
		if _, err := txRepo.ByIdempotencyKey(h.ctx, derivedTxKey(a.idem, offer)); err != nil {
			t.Errorf("row for offer %q must exist: %v", offer.GetOfferId(), err)
		}
	}
	// Charged once per item: 10.00 seed less two items at 0.05.
	bal, err := h.billing.GetBalance(h.ctx, h.billingRef)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if want := mustBillingAmount(t, "9.90", "USD"); bal.Value.Cmp(want.Value) != 0 {
		t.Errorf("balance = %s, want 9.90 (two items at 0.05 charged once each)",
			bal.Value.FloatString(4))
	}
}

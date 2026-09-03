//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// TestReportUsage_CrossTenantRejected exercises the authz boundary: agent-A
// (registered with tenant A) executes a transaction; agent-B (registered
// with tenant B, signing with its own key) attempts to ReportUsage against
// agent-A's (transaction_id, billing_id). Authz MUST reject with
// PermissionDenied and the obligation state MUST stay PENDING.
//
// This is the canary for the missing self-act authz check: without
// caller-identity authorization the second tenant could overwrite the
// first tenant's audit row.
func TestReportUsage_CrossTenantRejected(t *testing.T) {
	h := newTestHarness(t) // tenant A + agent-test
	txID, billingID := executeTransactionFor(t, h, 100)

	// Stand up a second tenant + agent under the same Exchange.
	_, agentBClient := h.addTenant(t, "tenantb", "agent-b")

	_, err := agentBClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-cross", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})))
	assertConnectError(t, err, connect.CodePermissionDenied, "may not act")
	// State stays PENDING — no audit row from this call.
	assertObligationState(t, h, txID, "PENDING", "")
}

// TestReportUsage_BrokerRelay_Allowed verifies that a registered BROKER
// caller succeeds when the tenant has allow_broker_relay=true.
func TestReportUsage_BrokerRelay_Allowed(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)
	h.enableBrokerRelay(t, h.tenantID)
	brokerClient := h.addCaller(t, "broker-trusted", "BROKER")

	resp, err := brokerClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-broker-ok", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})))
	if err != nil {
		t.Fatalf("broker relay (allowed): %v", err)
	}
	if resp.Msg.GetReportId() == "" {
		t.Errorf("broker relay: accepted report missing report_id")
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_BrokerRelay_Denied verifies that a registered BROKER
// caller is rejected with PermissionDenied when the tenant has NOT
// opted into broker relay.
func TestReportUsage_BrokerRelay_Denied(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)
	// Deliberately do NOT call h.enableBrokerRelay — tenant's flag stays false.
	brokerClient := h.addCaller(t, "broker-untrusted", "BROKER")

	_, err := brokerClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-broker-no", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})))
	assertConnectError(t, err, connect.CodePermissionDenied, "broker")
	assertObligationState(t, h, txID, "PENDING", "")
}

// TestExecuteTransaction_CrossTenantRejected mirrors the authz boundary
// for ExecuteTransaction: agent-B (signing with its own key) attempts to
// execute a transaction naming requester.id="agent-test" (which belongs
// to tenant A). Authz MUST reject with PermissionDenied.
// TestExecuteTransaction_CrossTenantRejected pins the cross-identity guard under
// the R4 contract: agent identity is proven by the BODY offer-acceptance
// signature against the CLAIMED agent's REGISTERED key. A caller from another
// tenant (agent-c) cannot forge an agent-test acceptance — it lacks agent-test's
// private key — so a request claiming requester.id = agent-test but carrying an
// acceptance signed by a foreign key is rejected SIGNATURE_INVALID, with no side
// effect. (Pre-R4 this was a transport-keyid PermissionDenied "may not act"; R4
// relocates identity from the transport sig to the body acceptance.)
func TestExecuteTransaction_CrossTenantRejected(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	_, agentBClient := h.addTenant(t, "tenantc", "agent-c")

	const txID = "tx-cross"
	requester := newRequester("agent-test", "agent.example")
	// Falsely claim to be agent-test while supplying an acceptance signed by a
	// key that is NOT agent-test's registered key.
	forged := mintWrongKeyAcceptanceFor(t, offer, requester, txID)
	resp, err := agentBClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: helpers.ProtocolVersion, IdempotencyKey: txID,
		Requester: requester,
		Items:     []*rampv1.TransactionItem{{Offer: offer, AgentAcceptance: forged}},
	}))
	// The forged acceptance → KindSignatureInvalid, a denial-map kind → in-body
	// per-item denial after the C4 collapse (Flag #1). Strength preserved:
	// SIGNATURE_INVALID + no transaction.
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)
	assertNoTransaction(t, h, txID+":"+offer.GetOfferId())
}

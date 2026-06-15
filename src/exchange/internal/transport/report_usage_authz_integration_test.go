//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
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

	_, err := agentBClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-cross",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
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

	resp, err := brokerClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-broker-ok",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	if err != nil {
		t.Fatalf("broker relay (allowed): %v", err)
	}
	if !resp.Msg.GetAccepted() {
		t.Errorf("broker relay accepted=false")
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

	_, err := brokerClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-broker-no",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	assertConnectError(t, err, connect.CodePermissionDenied, "broker")
	assertObligationState(t, h, txID, "PENDING", "")
}

// TestExecuteTransaction_CrossTenantRejected mirrors the authz boundary
// for ExecuteTransaction: agent-B (signing with its own key) attempts to
// execute a transaction naming requester.id="agent-test" (which belongs
// to tenant A). Authz MUST reject with PermissionDenied.
func TestExecuteTransaction_CrossTenantRejected(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	_, agentBClient := h.addTenant(t, "tenantc", "agent-c")

	_, err := agentBClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-cross",
		OfferId:        stringPtr(offer.GetOfferId()),
		OfferSignature: stringPtr(offer.GetSignature()),
		// Falsely claim to be agent-test (tenant A's agent) while signing
		// with agent-c's key (tenant C).
		Requester: &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}))
	assertConnectError(t, err, connect.CodePermissionDenied, "may not act")
}

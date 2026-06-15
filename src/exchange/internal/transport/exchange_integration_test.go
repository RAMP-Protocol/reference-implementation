//go:build integration

package transport_test

import (
	"context"
	"net/url"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestSmoke walks the full scrappy-demo happy path.
func TestSmoke_PushDiscoverExecuteReport(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx

	// 1. PushResources via CatalogService. EstimatedQuantity is set so the
	// reporting-side tolerance check has something to compare against — the
	// new zero-estimate-rejects-non-zero-consumed rule means
	// EstimatedQuantity must be non-zero whenever the smoke path reports
	// a non-zero ConsumedQuantity.
	smokeEstimated := int32(50)
	pushResp, err := h.catalogClient.PushResources(ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{{
			Domain:            h.tenantDomain,
			Path:              "/articles/hello",
			EstimatedQuantity: &smokeEstimated,
		}},
	}))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if pushResp.Msg.GetAccepted() != 1 {
		t.Fatalf("accepted = %d", pushResp.Msg.GetAccepted())
	}

	// 2. DiscoverResources.
	discovered, err := h.exchangeClient.DiscoverResources(ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Id: "q-1",
		Requester: &rampv1.Requester{
			Id:     "agent-test",
			Domain: "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris:   []string{"https://" + h.tenantDomain + "/articles/hello"},
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	offers := discovered.Msg.GetOffers()
	if len(offers) != 1 {
		t.Fatalf("offers len = %d", len(offers))
	}
	offer := offers[0]
	if offer.GetSignature() == "" || offer.GetSignatureAlgorithm() != "EdDSA" {
		t.Fatalf("offer signature not populated: %+v", offer)
	}

	// 3. ExecuteTransaction. Signed URL lands on the canonical retrieval_endpoint.
	offerID := offer.GetOfferId()
	offerSig := offer.GetSignature()
	execResp, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-1",
		OfferId:        stringPtr(offerID),
		OfferSignature: stringPtr(offerSig),
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example",
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if execResp.Msg.GetTransactionId() == "" {
		t.Fatal("transaction id empty")
	}
	signedURL := extractSignedURL(t, execResp.Msg)
	if _, err := url.Parse(signedURL); err != nil {
		t.Fatalf("signed url parse: %v", err)
	}

	assertTransactionLogged(t, ctx, h, "tx-1")

	// 4. ReportUsage marks obligation RECEIVED.
	if _, err := h.exchangeClient.ReportUsage(ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-1",
		TransactionId: execResp.Msg.GetTransactionId(),
		BillingId:     execResp.Msg.GetBillingId(),
		Usage:         &rampv1.Usage{ConsumedQuantity: 42, Function: []string{"ai_input"}},
	})); err != nil {
		t.Fatalf("report: %v", err)
	}

	assertObligationState(t, h, execResp.Msg.GetTransactionId(), "RECEIVED", "VALIDATED")
}

// assertTransactionLogged verifies the transaction_log row exists by
// idempotency key.
func assertTransactionLogged(t *testing.T, ctx context.Context, h *testHarness, txRequestID string) {
	t.Helper()
	row, err := h.queries.GetTransactionByRequestID(ctx, txRequestID)
	if err != nil {
		t.Fatalf("GetTransactionByRequestID: %v", err)
	}
	if row.TxRequestID != txRequestID {
		t.Fatalf("tx_request_id = %q", row.TxRequestID)
	}
	if len(row.SignedUrlHash) != 32 {
		t.Fatalf("signed_url_hash len = %d", len(row.SignedUrlHash))
	}
}

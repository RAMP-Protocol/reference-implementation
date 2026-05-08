//go:build integration

package transport_test

import (
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
)

// TestExecuteTransaction_SignatureInvalid asserts that a tampered offer
// signature is rejected with Unauthenticated.
func TestExecuteTransaction_SignatureInvalid(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx

	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	// tamper signature
	bogus := offers[0].GetSignature() + "00"
	offerID := offers[0].GetOfferId()

	_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-bad",
		OfferId:        stringPtr(offerID),
		OfferSignature: stringPtr(bogus),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}))
	if err == nil {
		t.Fatal("expected signature rejection")
	}
	var ce *connect.Error
	if !connectAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	if ce.Code() != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", ce.Code())
	}
}

// TestExecuteTransaction_BillingDenied confirms denial when the agent has
// no balance configured.
func TestExecuteTransaction_BillingDenied(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	// Drain balance so authorize fails.
	_, _ = h.billing.Authorize(ctx, tenantDrain(t))
	offerID := offer.GetOfferId()
	offerSig := offer.GetSignature()
	_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-drain",
		OfferId:        stringPtr(offerID),
		OfferSignature: stringPtr(offerSig),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}))
	if err == nil {
		t.Fatal("expected billing denial")
	}
	var ce *connect.Error
	if !connectAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	if ce.Code() != connect.CodePermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", ce.Code())
	}
}

// TestExecuteTransaction_Idempotency rejects duplicate tx_request_id replays.
func TestExecuteTransaction_Idempotency(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx
	seedCatalog(t, h)
	offers := discoverFirst(t, h)
	offer := offers[0]

	offerID := offer.GetOfferId()
	offerSig := offer.GetSignature()
	req := &rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-dup",
		OfferId:        stringPtr(offerID),
		OfferSignature: stringPtr(offerSig),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}
	if _, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req)); err != nil {
		t.Fatalf("first call: %v", err)
	}
	_, err := h.exchangeClient.ExecuteTransaction(ctx, connect.NewRequest(req))
	if err == nil {
		t.Fatal("expected idempotent denial")
	}
	var ce *connect.Error
	if !connectAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	if ce.Code() != connect.CodeAlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", ce.Code())
	}
	if !strings.Contains(ce.Message(), "tx_request_id") {
		t.Errorf("message = %q", ce.Message())
	}
}

// ---- helpers --------------------------------------------------------------

func seedCatalog(t *testing.T, h *testHarness) {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "test-caller",
		Entries:  []*rampv1.ResourceEntry{{Domain: h.tenantDomain, Path: "/articles/hello"}},
	}))
	if err != nil {
		t.Fatalf("seed push: %v", err)
	}
}

func discoverFirst(t *testing.T, h *testHarness) []*rampv1.Offer {
	t.Helper()
	resp, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Id: "q", Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
			Uris: []string{"https://" + h.tenantDomain + "/articles/hello"},
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(resp.Msg.GetOffers()) == 0 {
		t.Fatal("no offers returned")
	}
	return resp.Msg.GetOffers()
}

// connectAs is a tiny wrapper around errors.As for *connect.Error to keep
// the test ergonomics compact.
func connectAs(err error, target **connect.Error) bool {
	return ceAs(err, target)
}

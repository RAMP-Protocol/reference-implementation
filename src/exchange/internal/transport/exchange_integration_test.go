//go:build integration

package transport_test

import (
	"context"
	"net/url"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestSmoke walks the full scrappy-demo happy path.
func TestSmoke_PushDiscoverExecuteReport(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx

	// 1. PushResources via CatalogService. Pricing (and its estimated_quantity)
	// is carried on a LicenseTerm now: the term is the sole source of
	// the offer price, and its Pricing.estimated_quantity feeds the reporting-side
	// tolerance check — the zero-estimate-rejects-non-zero-consumed rule means the
	// estimate must be non-zero whenever the smoke path reports a non-zero
	// ConsumedQuantity.
	smokeEstimated := int32(50)
	smokeUnit := "accesses"
	pushResp, err := h.catalogClient.PushResources(ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.tenantDomain,
			Path:   "/articles/hello",
			Terms: []*rampv1.LicenseTerm{{
				Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing: &rampv1.Pricing{
					Model:             rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
					Rate:              "0.05",
					Currency:          "USD",
					Unit:              &smokeUnit,
					EstimatedQuantity: &smokeEstimated,
				},
			}},
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
		Ver:  "1.0",
		Uris: []string{"https://" + h.tenantDomain + "/articles/hello"},
		Requester: &rampv1.Requester{
			Id:     "agent-test",
			Domain: "agent.example",
			Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// Version-skew fix: the Exchange MUST stamp Ver = "1.0" on the RAMP responses
	// it emits. Assert the literal (not rampproto.Ver) so a regression in the
	// constant fails here instead of echoing whatever value it currently holds.
	if got := discovered.Msg.GetVer(); got != "1.0" {
		t.Errorf("DiscoverResources response Ver = %q, want %q", got, "1.0")
	}
	offers := discovered.Msg.GetOffers()
	if len(offers) != 1 {
		t.Fatalf("offers len = %d", len(offers))
	}
	offer := offers[0]
	if offer.GetSignature() == "" || offer.GetSignatureAlgorithm() != "EdDSA" {
		t.Fatalf("offer signature not populated: %+v", offer)
	}

	// 3. ExecuteTransaction (items-only contract after the C4 collapse). The
	// signed URL lands on the single result item's retrieval_endpoint, and the
	// per-item transaction_id / billing_id feed ReportUsage.
	execResp, err := executeSingleItem(t, h, "tx-1", offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// Version-skew coverage (orthogonal, adopted from v1.1): the items-only
	// TransactionResponse still stamps the top-level Ver, so this assertion holds
	// against the collapsed contract.
	if got := execResp.Msg.GetVer(); got != "1.0" {
		t.Errorf("ExecuteTransaction response Ver = %q, want %q", got, "1.0")
	}
	// Items-only contract (C4 collapse): the transaction_id lives on the single
	// result item, not at the top level.
	item := singleResultItem(t, execResp)
	if item.GetTransactionId() == "" {
		t.Fatal("transaction id empty")
	}
	signedURL := itemSignedURL(t, execResp)
	if _, err := url.Parse(signedURL); err != nil {
		t.Fatalf("signed url parse: %v", err)
	}

	// The items[] path persists under the DERIVED key idempotency_key:offer_id.
	assertTransactionLogged(t, ctx, h, "tx-1"+":"+offer.GetOfferId())

	// 4. ReportUsage marks obligation RECEIVED.
	if _, err := h.exchangeClient.ReportUsage(ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-1",
		TransactionId: item.GetTransactionId(),
		BillingId:     item.GetBillingId(),
		Usage:         &rampv1.Usage{ConsumedQuantity: 42, Function: []string{"ai_input"}},
	})); err != nil {
		t.Fatalf("report: %v", err)
	}

	assertObligationState(t, h, item.GetTransactionId(), "RECEIVED", "VALIDATED")
}

// assertTransactionLogged verifies the transaction_log row exists by
// idempotency key.
func assertTransactionLogged(t *testing.T, ctx context.Context, h *testHarness, idempotencyKey string) {
	t.Helper()
	// Production repository surface, not the raw sqlc Querier (Testing Doctrine pt9).
	rec, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(ctx, idempotencyKey)
	if err != nil {
		t.Fatalf("TransactionRepo.ByIdempotencyKey: %v", err)
	}
	if rec.IdempotencyKey != idempotencyKey {
		t.Fatalf("idempotency_key = %q", rec.IdempotencyKey)
	}
	if len(rec.SignedURLHash) != 32 {
		t.Fatalf("signed_url_hash len = %d", len(rec.SignedURLHash))
	}
}

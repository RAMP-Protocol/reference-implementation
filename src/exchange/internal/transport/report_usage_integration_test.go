//go:build integration

package transport_test

import (
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// pushDiscoverOffer pushes a catalog entry under the harness tenant with the
// given EstimatedQuantity, discovers it, and returns the first offer. Shared by
// executeTransactionFor and the hot-path-failure tests.
func pushDiscoverOffer(t *testing.T, h *testHarness, estimatedQty int32) *rampv1.Offer {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{{
			Domain:            h.tenantDomain,
			Path:              "/articles/hello",
			EstimatedQuantity: &estimatedQty,
		}},
	}))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	return discoverFirst(t, h)[0]
}

// executeOfferRaw runs ExecuteTransaction for the given offer and returns the
// raw response/error WITHOUT fataling, so failure-path tests can assert on the
// error. The tx_request_id is derived from t.Name() to stay unique across tests.
func executeOfferRaw(
	t *testing.T, h *testHarness, offer *rampv1.Offer,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	return h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", Id: "tx-" + t.Name(),
		OfferId:        stringPtr(offer.GetOfferId()),
		OfferSignature: stringPtr(offer.GetSignature()),
		Requester:      &rampv1.Requester{Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
	}))
}

// executeTransactionFor pushes a catalog entry, discovers an offer, executes
// the transaction, and returns the transaction_id and billing_id. estimatedQty
// controls the offer's EstimatedQuantity (drives the obligation's
// estimated_quantity column, used by the tolerance check). The pre-rename
// `executeAndReport` was a misnomer — this helper only executes, it never
// reports (review §D).
func executeTransactionFor(t *testing.T, h *testHarness, estimatedQty int32) (txID, billingID string) {
	t.Helper()
	offer := pushDiscoverOffer(t, h, estimatedQty)
	execResp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return execResp.Msg.GetTransactionId(), execResp.Msg.GetBillingId()
}

// seedTenantPolicy seeds a tenants.reporting_policy JSONB row via the
// generated sqlc Querier (no raw SQL).
func seedTenantPolicy(t *testing.T, h *testHarness, policyJSON string) {
	t.Helper()
	if err := h.queries.SetTenantReportingPolicy(h.ctx, sqlc.SetTenantReportingPolicyParams{
		TenantID:        h.tenantID,
		ReportingPolicy: []byte(policyJSON),
	}); err != nil {
		t.Fatalf("set tenant reporting policy: %v", err)
	}
}

// TestReportUsage_HappyPath verifies that a well-formed report is accepted,
// the obligation flips to RECEIVED, validation_outcome=VALIDATED, and the
// response carries Accepted=true plus a non-empty ReportId. Together these
// pin the protocol's dispute-chain anchor.
func TestReportUsage_HappyPath(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-1",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !resp.Msg.GetAccepted() {
		t.Errorf("response Accepted=false, want true")
	}
	if resp.Msg.GetReportId() == "" {
		t.Errorf("response ReportId empty")
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_RequiredFields_FromTenantPolicy seeds required_fields
// through tenants.reporting_policy and verifies the validator rejects a
// report missing the field. Replaces the raw-SQL injection path the first
// cut of this MR used.
func TestReportUsage_RequiredFields_FromTenantPolicy(t *testing.T) {
	h := newTestHarness(t)
	seedTenantPolicy(t, h, `{"required_fields":["billing_id"]}`)
	txID, _ := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-req",
		TransactionId: txID,
		BillingId:     "", // required but missing
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_FIELDS")
}

// TestReportUsage_WindowExpired advances the deterministic clock past the
// reporting window and asserts the report is rejected.
func TestReportUsage_WindowExpired(t *testing.T) {
	start := time.Now().UTC()
	det := clock.NewDeterministic(start)
	h := newTestHarnessWithClock(t, det)
	txID, billingID := executeTransactionFor(t, h, 0)

	det.Advance(25 * time.Hour)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-window",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 0},
	}))
	assertConnectError(t, err, connect.CodeFailedPrecondition, "window")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_WINDOW")
}

// TestReportUsage_ToleranceViolation sends a consumed quantity outside ±20%.
func TestReportUsage_ToleranceViolation(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-tol",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 200},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "outside")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")
}

// TestReportUsage_ToleranceAtBoundary_Plus20 verifies exactly +20% passes.
func TestReportUsage_ToleranceAtBoundary_Plus20(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-bound-plus",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 120},
	}))
	if err != nil {
		t.Fatalf("expected pass at +20%%, got: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_ToleranceAtBoundary_Minus20 mirrors the +20% boundary test
// in the negative direction (review finding L9).
func TestReportUsage_ToleranceAtBoundary_Minus20(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-bound-minus",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 80},
	}))
	if err != nil {
		t.Fatalf("expected pass at -20%%, got: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_BillingIDMismatch sends a wrong billing_id.
func TestReportUsage_BillingIDMismatch(t *testing.T) {
	h := newTestHarness(t)
	txID, _ := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-billing",
		TransactionId: txID,
		BillingId:     "wrong-billing-id",
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_BILLING_ID")
}

// TestReportUsage_UnknownTransaction verifies a clear NotFound response.
func TestReportUsage_UnknownTransaction(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-unknown",
		TransactionId: "nonexistent-tx",
		BillingId:     "b",
		Usage:         &rampv1.Usage{ConsumedQuantity: 1},
	}))
	assertConnectCode(t, err, connect.CodeNotFound)
}

// TestReportUsage_ZeroEstimate_NonZeroConsumed_Rejected exercises the Q2
// strict-reject decision: an obligation with estimated_quantity=0 must
// reject any non-zero consumed_quantity.
func TestReportUsage_ZeroEstimate_NonZeroConsumed_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 0)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-ze",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 1},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "zero-estimate")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")
}

// TestReportUsage_ZeroEstimate_ZeroConsumed_Accepted is the paired
// counterpart — zero against zero passes (boundary case).
func TestReportUsage_ZeroEstimate_ZeroConsumed_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 0)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-zz",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 0},
	}))
	if err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_NegativeConsumed_Rejected pins that the validator rejects
// negative consumed quantities (review finding L12).
func TestReportUsage_NegativeConsumed_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-neg",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: -1},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "negative")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")
}

// TestReportUsage_TimestampInFuture_Rejected covers the L6 remainder
// timestamp skew check on the future side.
func TestReportUsage_TimestampInFuture_Rejected(t *testing.T) {
	start := time.Now().UTC()
	det := clock.NewDeterministic(start)
	h := newTestHarnessWithClock(t, det)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-ts-future",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		Timestamp:     timestamppb.New(det.Now().Add(10 * time.Minute)),
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "future")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TIMESTAMP")
}

// TestReportUsage_TimestampBeforeTransaction_Rejected covers the L6
// remainder timestamp skew check on the past side.
func TestReportUsage_TimestampBeforeTransaction_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-ts-past",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		Timestamp:     timestamppb.New(time.Now().Add(-2 * time.Hour)),
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "precedes")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TIMESTAMP")
}

// TestReportUsage_TimestampUnset_Accepted confirms unset timestamp is fine.
func TestReportUsage_TimestampUnset_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-ts-unset",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	if err != nil {
		t.Fatalf("expected pass with unset timestamp, got: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_ExchangeMismatch_Rejected covers the L6 remainder
// exchange cross-check.
func TestReportUsage_ExchangeMismatch_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	wrong := "evil.example"
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-mp-bad",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		Exchange:      &wrong,
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "exchange")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_EXCHANGE")
}

// TestReportUsage_ExchangeUnset_Accepted confirms the exchange check
// is opt-in by the caller.
func TestReportUsage_ExchangeUnset_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-mp-unset",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	if err != nil {
		t.Fatalf("expected pass with unset exchange, got: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_DuplicateIdempotent verifies that two calls carrying the
// same UsageReport.id return the same ReportId and only one DB write
// occurs (UsageReport.id is the idempotency anchor).
func TestReportUsage_DuplicateIdempotent(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	build := func() *connect.Request[rampv1.UsageReport] {
		return connect.NewRequest(&rampv1.UsageReport{
			Ver: "1.0", Id: "r-dup",
			TransactionId: txID,
			BillingId:     billingID,
			Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		})
	}

	first, err := h.exchangeClient.ReportUsage(h.ctx, build())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := h.exchangeClient.ReportUsage(h.ctx, build())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Msg.GetReportId() == "" || first.Msg.GetReportId() != second.Msg.GetReportId() {
		t.Fatalf("idempotent calls returned different report_ids: %q vs %q",
			first.Msg.GetReportId(), second.Msg.GetReportId())
	}
	if !second.Msg.GetAccepted() {
		t.Errorf("second response Accepted=false, want true (idempotent replay)")
	}
}

// TestReportUsage_AlreadyReported verifies that a second call with a NEW
// UsageReport.id against an already-RECEIVED obligation fails with
// FailedPrecondition (state guard fires).
func TestReportUsage_AlreadyReported(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	if _, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-first",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	})); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-second-different-id",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	assertConnectError(t, err, connect.CodeFailedPrecondition, "already")
	// State stays RECEIVED (first call already transitioned).
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_RejectedThenCorrected verifies that a rejected report
// leaves the obligation in PENDING and a corrected second call (with a
// different UsageReport.id) succeeds.
func TestReportUsage_RejectedThenCorrected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	// First call — outside tolerance.
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-bad",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 200},
	}))
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")

	// Second call — corrected.
	if _, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", Id: "r-good",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	})); err != nil {
		t.Fatalf("corrected call: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

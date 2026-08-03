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
	// Pricing (including estimated_quantity, which drives the obligation
	// tolerance window) is term-derived now.
	return pushDiscoverTermOffer(t, h, "/articles/hello", seedPricedTermEst(estimatedQty))
}

// pushDiscoverTermOffer pushes a single-entry catalog at path carrying term
// through the public PushResources surface, discovers path, and returns the
// first offer. The shared Agent→Exchange ingest+discovery round-trip: the priced
// (pushDiscoverOffer) and free-resource suites both reuse it, so a PER_UNIT term
// and a FREE term exercise the identical public path with no raw-sqlc arrange
// (Testing Doctrine §9).
func pushDiscoverTermOffer(t *testing.T, h *testHarness, path string, term *rampv1.LicenseTerm) *rampv1.Offer {
	t.Helper()
	_, err := h.catalogClient.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.tenantDomain,
			Path:   path,
			Terms:  []*rampv1.LicenseTerm{term},
		}},
	}))
	if err != nil {
		t.Fatalf("push %s: %v", path, err)
	}
	return discoverPath(t, h, path)[0]
}

// executeOfferRaw runs ExecuteTransaction for the given offer and returns the
// raw response/error WITHOUT fataling, so failure-path tests can assert on the
// error. The idempotency_key is derived from t.Name() to stay unique across tests.
func executeOfferRaw(
	t *testing.T, h *testHarness, offer *rampv1.Offer,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	return executeOfferRawWithID(t, h, offer, "tx-"+t.Name())
}

// executeOfferRawWithID is executeOfferRaw with an explicit idempotency_key, for
// tests that drive two transactions in one body — a second call sharing the
// id would hit the idempotency short-circuit instead of reaching the handler.
// Items-only contract (C4 collapse): the offer is presented as a single items[]
// entry with a body AgentAcceptance, via the shared executeSingleItem helper.
func executeOfferRawWithID(
	t *testing.T, h *testHarness, offer *rampv1.Offer, id string,
) (*connect.Response[rampv1.TransactionResponse], error) {
	t.Helper()
	return executeSingleItem(t, h, id, offer)
}

// executeTransactionFor pushes a catalog entry, discovers an offer, executes
// the transaction, and returns the transaction_id and billing_id. estimatedQty
// controls the offer's EstimatedQuantity (drives the obligation's
// estimated_quantity column, used by the tolerance check). The pre-rename
// `executeAndReport` was a misnomer — this helper only executes, it never
// reports.
func executeTransactionFor(t *testing.T, h *testHarness, estimatedQty int32) (txID, billingID string) {
	t.Helper()
	offer := pushDiscoverOffer(t, h, estimatedQty)
	execResp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	item := singleResultItem(t, execResp)
	return item.GetTransactionId(), item.GetBillingId()
}

// seedTenantPolicy seeds a tenants.reporting_policy JSONB row via the
// generated sqlc Querier (no raw SQL).
func seedTenantPolicy(t *testing.T, h *testHarness, policyJSON string) {
	t.Helper()
	if _, err := h.queries.SetTenantReportingPolicy(h.ctx, sqlc.SetTenantReportingPolicyParams{
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
		Ver: "1.0", IdempotencyKey: "r-1",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	// Acceptance is no longer an in-body flag (ADR-019 §2): a successful report
	// returns no transport error and carries the issued report_id.
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
		Ver: "1.0", IdempotencyKey: "r-req",
		TransactionId: txID,
		BillingId:     "", // required but missing
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertReportRejectionField(t, err, "billing_id")
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
		Ver: "1.0", IdempotencyKey: "r-window",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 0},
	}))
	assertConnectError(t, err, connect.CodeFailedPrecondition, "window")
	assertReportRejectionField(t, err, "window")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_WINDOW")
}

// TestReportUsage_ToleranceViolation sends a consumed quantity outside ±20%.
func TestReportUsage_ToleranceViolation(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-tol",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 200},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "outside")
	assertReportRejectionField(t, err, "consumed_quantity")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")
}

// TestReportUsage_ToleranceAtBoundary_Plus20 verifies exactly +20% passes.
func TestReportUsage_ToleranceAtBoundary_Plus20(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-bound-plus",
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
// in the negative direction.
func TestReportUsage_ToleranceAtBoundary_Minus20(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-bound-minus",
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
		Ver: "1.0", IdempotencyKey: "r-billing",
		TransactionId: txID,
		BillingId:     "wrong-billing-id",
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertReportRejectionField(t, err, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_BILLING_ID")
}

// TestReportUsage_UnknownTransaction verifies a clear NotFound response.
func TestReportUsage_UnknownTransaction(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-unknown",
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
		Ver: "1.0", IdempotencyKey: "r-ze",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 1},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "zero-estimate")
	assertReportRejectionField(t, err, "consumed_quantity")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")
}

// TestReportUsage_ZeroEstimate_ZeroConsumed_Accepted is the paired
// counterpart — zero against zero passes (boundary case).
func TestReportUsage_ZeroEstimate_ZeroConsumed_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 0)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-zz",
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
// negative consumed quantities.
func TestReportUsage_NegativeConsumed_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-neg",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: -1},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "negative")
	assertReportRejectionField(t, err, "consumed_quantity")
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
		Ver: "1.0", IdempotencyKey: "r-ts-future",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		Timestamp:     timestamppb.New(det.Now().Add(10 * time.Minute)),
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "future")
	assertReportRejectionField(t, err, "timestamp")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TIMESTAMP")
}

// TestReportUsage_TimestampBeforeTransaction_Rejected covers the L6
// remainder timestamp skew check on the past side.
func TestReportUsage_TimestampBeforeTransaction_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-ts-past",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		Timestamp:     timestamppb.New(time.Now().Add(-2 * time.Hour)),
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "precedes")
	assertReportRejectionField(t, err, "timestamp")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TIMESTAMP")
}

// TestReportUsage_TimestampUnset_Accepted confirms unset timestamp is fine.
func TestReportUsage_TimestampUnset_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-ts-unset",
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
		Ver: "1.0", IdempotencyKey: "r-mp-bad",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		Exchange:      &wrong,
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "exchange")
	assertReportRejectionField(t, err, "exchange")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_EXCHANGE")
}

// TestReportUsage_ExchangeUnset_Accepted confirms the exchange check
// is opt-in by the caller.
func TestReportUsage_ExchangeUnset_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-mp-unset",
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
			Ver: "1.0", IdempotencyKey: "r-dup",
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
}

// TestReportUsage_AlreadyReported verifies that a second call with a NEW
// UsageReport.id against an already-RECEIVED obligation fails with
// FailedPrecondition (state guard fires).
func TestReportUsage_AlreadyReported(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	if _, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-first",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	})); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-second-different-id",
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
		Ver: "1.0", IdempotencyKey: "r-bad",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 200},
	}))
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")

	// Second call — corrected.
	if _, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-good",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	})); err != nil {
		t.Fatalf("corrected call: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_FreeTx_EmptyBillingID_Accepted pins the free-path report
// contract: a zero-cost transaction persists billing_id NULL (ADR-009 D2/D5),
// so a conformant report carries no billing_id and validates (empty == empty).
// consumed_quantity is 0 because the FREE term seeds estimated_quantity 0.
func TestReportUsage_FreeTx_EmptyBillingID_Accepted(t *testing.T) {
	h := newTestHarness(t)
	offer := pushDiscoverTermOffer(t, h, "/articles/free-report", seedFreeTerm())
	execResp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute free offer: %v", err)
	}
	txID := singleResultItem(t, execResp).GetTransactionId()

	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-free-empty",
		TransactionId: txID,
		BillingId:     "",
		Usage:         &rampv1.Usage{ConsumedQuantity: 0},
	}))
	if err != nil {
		t.Fatalf("free report with empty billing_id: %v", err)
	}
	if resp.Msg.GetReportId() == "" {
		t.Error("response ReportId empty")
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_FreeTx_NonEmptyBillingID_Rejected pins the threat-model T25
// gate on the free path: the transaction stored no billing_id, so a report
// naming a non-empty handle is a reservation absent from this Exchange's
// transaction log — a forged handle rejected with InvalidArgument, and the
// obligation stays PENDING (no side effect).
func TestReportUsage_FreeTx_NonEmptyBillingID_Rejected(t *testing.T) {
	h := newTestHarness(t)
	offer := pushDiscoverTermOffer(t, h, "/articles/free-report-forged", seedFreeTerm())
	execResp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute free offer: %v", err)
	}
	txID := singleResultItem(t, execResp).GetTransactionId()

	_, err = h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-free-forged",
		TransactionId: txID,
		BillingId:     "forged-handle",
		Usage:         &rampv1.Usage{ConsumedQuantity: 0},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertReportRejectionField(t, err, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_BILLING_ID")
}

// TestReportUsage_FreeTx_BillingIDRequired_EmptyAccepted pins the interaction
// between a tenant policy that lists billing_id in required_fields and the free
// path. A price-zero transaction stores no billing_id (ADR-009 D5), so the
// obligation drops billing_id from its required set at build time and a
// conformant empty-billing_id report validates. Without the free-path strip this
// report is un-fileable: the empty billing_id is rejected at the required-fields
// gate, and any non-empty value is rejected as a forged handle.
func TestReportUsage_FreeTx_BillingIDRequired_EmptyAccepted(t *testing.T) {
	h := newTestHarness(t)
	// Seed BEFORE execute: the obligation captures required_fields at execute time.
	seedTenantPolicy(t, h, `{"required_fields":["billing_id"]}`)
	offer := pushDiscoverTermOffer(t, h, "/articles/free-billing-required", seedFreeTerm())
	execResp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute free offer: %v", err)
	}
	txID := singleResultItem(t, execResp).GetTransactionId()

	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-free-req-empty",
		TransactionId: txID,
		BillingId:     "",
		Usage:         &rampv1.Usage{ConsumedQuantity: 0},
	}))
	if err != nil {
		t.Fatalf("free report with empty billing_id under billing_id-required policy: %v", err)
	}
	if resp.Msg.GetReportId() == "" {
		t.Error("response ReportId empty")
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_FreeTx_BillingIDRequired_ForgedRejected is the negative path:
// even when the tenant requires billing_id, a free-path report naming a non-empty
// handle is still rejected as forged (threat model T25). The free-path strip
// removes the unsatisfiable required-fields gate without weakening the billing_id
// existence check, so the rejection is REJECTED_BILLING_ID (not REJECTED_FIELDS)
// and the obligation stays PENDING.
func TestReportUsage_FreeTx_BillingIDRequired_ForgedRejected(t *testing.T) {
	h := newTestHarness(t)
	seedTenantPolicy(t, h, `{"required_fields":["billing_id"]}`)
	offer := pushDiscoverTermOffer(t, h, "/articles/free-billing-required-forged", seedFreeTerm())
	execResp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute free offer: %v", err)
	}
	txID := singleResultItem(t, execResp).GetTransactionId()

	_, err = h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-free-req-forged",
		TransactionId: txID,
		BillingId:     "forged-handle",
		Usage:         &rampv1.Usage{ConsumedQuantity: 0},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertReportRejectionField(t, err, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_BILLING_ID")
}

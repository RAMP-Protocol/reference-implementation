//go:build integration

package transport_test

import (
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

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
	item := executeOne(t, h, "tx-"+t.Name(), estimatedQty)
	return item.GetTransactionId(), item.GetBillingId()
}

// executeOne runs one transaction for the default caller and returns the
// delivered item, failing the test if the item was denied. estQty rides onto the
// obligation's estimated_quantity, which the tolerance check compares a report
// against.
//
// The denial check is the reason this is the single execute round-trip: a
// refusal the execute path classifies as a denial arrives in-body under HTTP
// 200, so a helper that only inspects the transport error hands back an item
// with empty ids and the failure surfaces somewhere else entirely.
func executeOne(t *testing.T, h *testHarness, key string, estQty int32) *rampv1.TransactionResultItem {
	t.Helper()
	resp, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, estQty), key)
	if err != nil {
		t.Fatalf("execute %q: %v", key, err)
	}
	item := singleResultItem(t, resp)
	if item.GetRetrievalEndpoint() == "" {
		t.Fatalf("execute %q was denied: %v", key, item.GetDenialReason())
	}
	return item
}

// reportFor files a conformant report for one delivered item and fails the test
// if it is not accepted. consumed must sit inside the obligation's tolerance.
func reportFor(t *testing.T, h *testHarness, key string, item *rampv1.TransactionResultItem, consumed int32) string {
	t.Helper()
	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport(
		key, item.GetTransactionId(), item.GetBillingId(), &rampv1.Usage{ConsumedQuantity: consumed},
	)))
	if err != nil {
		t.Fatalf("report %q: %v", key, err)
	}
	return resp.Msg.GetReportId()
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

	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-1", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})))
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

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-req", txID, "", &rampv1.Usage{ConsumedQuantity: 100})))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertReportRejectionField(t, err, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_FIELDS")
}

// TestReportUsage_AfterDeadline_Accepted advances the deterministic clock past
// the reporting window and asserts the report is ACCEPTED anyway.
//
// This is the deadlock fix at its narrowest. Rejecting a late report left the
// obligation PENDING, and a PENDING obligation past its deadline is what the
// execute gate refuses on, so an agent that missed one window could neither
// report nor transact. The obligation reaching RECEIVED/VALIDATED here is what
// gives the gate a remedy the agent can apply; that the remedy actually unblocks
// it is proved end-to-end in the recovery suite.
func TestReportUsage_AfterDeadline_Accepted(t *testing.T) {
	start := time.Now().UTC()
	det := clock.NewDeterministic(start)
	h := newTestHarnessWithClock(t, det)
	txID, billingID := executeTransactionFor(t, h, 0)

	det.Advance(pastReportingWindow)

	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-window", txID, billingID, &rampv1.Usage{ConsumedQuantity: 0})))
	if err != nil {
		t.Fatalf("report filed after the deadline must be accepted, got: %v", err)
	}
	if resp.Msg.GetReportId() == "" {
		t.Error("accepted report returned no report_id")
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_ToleranceViolation sends a consumed quantity outside ±20%.
func TestReportUsage_ToleranceViolation(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-tol", txID, billingID, &rampv1.Usage{ConsumedQuantity: 200})))
	assertConnectError(t, err, connect.CodeInvalidArgument, "outside")
	assertReportRejectionField(t, err, "consumed_quantity")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")
}

// TestReportUsage_ToleranceAtBoundary_Plus20 verifies exactly +20% passes.
func TestReportUsage_ToleranceAtBoundary_Plus20(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-bound-plus", txID, billingID, &rampv1.Usage{ConsumedQuantity: 120})))
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

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-bound-minus", txID, billingID, &rampv1.Usage{ConsumedQuantity: 80})))
	if err != nil {
		t.Fatalf("expected pass at -20%%, got: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_BillingIDMismatch sends a wrong billing_id.
func TestReportUsage_BillingIDMismatch(t *testing.T) {
	h := newTestHarness(t)
	txID, _ := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-billing", txID, "wrong-billing-id", &rampv1.Usage{ConsumedQuantity: 100})))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertReportRejectionField(t, err, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_BILLING_ID")
}

// TestReportUsage_UnknownTransaction verifies a clear NotFound response.
func TestReportUsage_UnknownTransaction(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-unknown", "nonexistent-tx", "b", &rampv1.Usage{ConsumedQuantity: 1})))
	assertConnectCode(t, err, connect.CodeNotFound)
}

// TestReportUsage_ZeroEstimate_NonZeroConsumed_Rejected exercises the Q2
// strict-reject decision: an obligation with estimated_quantity=0 must
// reject any non-zero consumed_quantity.
func TestReportUsage_ZeroEstimate_NonZeroConsumed_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 0)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-ze", txID, billingID, &rampv1.Usage{ConsumedQuantity: 1})))
	assertConnectError(t, err, connect.CodeInvalidArgument, "zero-estimate")
	assertReportRejectionField(t, err, "consumed_quantity")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")
}

// TestReportUsage_ZeroEstimate_ZeroConsumed_Accepted is the paired
// counterpart — zero against zero passes (boundary case).
func TestReportUsage_ZeroEstimate_ZeroConsumed_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 0)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-zz", txID, billingID, &rampv1.Usage{ConsumedQuantity: 0})))
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

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-neg", txID, billingID, &rampv1.Usage{ConsumedQuantity: -1})))
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

	report := newUsageReport("r-ts-future", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})
	report.Timestamp = timestamppb.New(det.Now().Add(10 * time.Minute))
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(report))
	assertConnectError(t, err, connect.CodeInvalidArgument, "future")
	assertReportRejectionField(t, err, "timestamp")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TIMESTAMP")
}

// TestReportUsage_TimestampBeforeTransaction_Rejected covers the L6
// remainder timestamp skew check on the past side.
func TestReportUsage_TimestampBeforeTransaction_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	report := newUsageReport("r-ts-past", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})
	report.Timestamp = timestamppb.New(time.Now().Add(-2 * time.Hour))
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(report))
	assertConnectError(t, err, connect.CodeInvalidArgument, "precedes")
	assertReportRejectionField(t, err, "timestamp")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TIMESTAMP")
}

// TestReportUsage_TimestampUnset_Accepted confirms unset timestamp is fine.
func TestReportUsage_TimestampUnset_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-ts-unset", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})))
	if err != nil {
		t.Fatalf("expected pass with unset timestamp, got: %v", err)
	}
	assertObligationState(t, h, txID, "RECEIVED", "VALIDATED")
}

// TestReportUsage_NamesAnotherExchange_Rejected drives a report that is
// well-formed in every other respect and names somebody else.
//
// This is the one of the three that the RECIPIENT CHECK answers: the value is a
// valid bare domain, so wire validation passes it through and only the audience
// comparison can refuse it. The assertion reads the check's own verdict rather
// than its sentence, which is what tells this case apart from the two above.
//
// The refusal happens before the obligation is loaded, so there is no
// obligation-level rejection to assert: the report leaves the transaction in the
// state it was already in, which is what the last assertion pins. That ordering
// is the point of the check — the transaction id a report carries is opaque and
// scoped to the Exchange that issued it, so answering "is this report for me"
// from the database would mean trusting the very claim under test.
func TestReportUsage_NamesAnotherExchange_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: helpers.ProtocolVersion, IdempotencyKey: "r-mp-bad",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		Exchange:      "other-exchange.example",
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "addressed to a different Exchange")
	assertRecipientRefusal(t, err, "mismatch")
	// The refusal is an exchange fault like any other, so it stamps the grouping
	// key every exchange fault stamps, and names the field in the spelling the
	// message uses. Neither was asserted anywhere: the interceptor could have
	// returned an empty domain, or the field of a different message shape, with
	// the whole suite passing.
	assertErrorDomain(t, err, exchangeServiceDomainLiteral)
	assertReportRejectionField(t, err, "exchange")
	assertObligationState(t, h, txID, "PENDING", "")
}

// TestReportUsage_NoExchange_Rejected pins the end of the opt-in posture. A
// report that names nobody used to pass, which made the recipient check
// something the SENDER could decline; it is now refused and the obligation is
// left untouched.
//
// The refusal comes from WIRE VALIDATION, not from the recipient check — an
// absent value fails the field's own pattern before any interceptor sees it.
// That is worth stating rather than glossing: an earlier version of this test
// asserted the substring "exchange" and read as proof that the recipient check
// ran, when the same assertion passed with the check removed entirely. The
// recipient check's own handling of an empty claim is covered where it lives,
// in internal/rampaudience.
func TestReportUsage_NoExchange_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: helpers.ProtocolVersion, IdempotencyKey: "r-mp-unset",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "validation error")
	assertObligationState(t, h, txID, "PENDING", "")
}

// TestReportUsage_MalformedExchange_Rejected covers a value that is not a bare
// domain at all. Like the empty case above, this one is answered by wire
// validation before the recipient check runs: the shape rule is on the field
// itself. The two are kept apart because they say different things to whoever
// reads the rejection, and because only one of them can reach the interceptor —
// see the mismatch case, which does.
func TestReportUsage_MalformedExchange_Rejected(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: helpers.ProtocolVersion, IdempotencyKey: "r-mp-malformed",
		TransactionId: txID,
		BillingId:     billingID,
		Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		Exchange:      "https://" + harnessExchangeDomain + "/report",
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "validation error")
	assertObligationState(t, h, txID, "PENDING", "")
}

// TestReportUsage_NamesThisExchange_Accepted is the positive half of the three
// tests above: the same report, correctly addressed, is validated and recorded.
func TestReportUsage_NamesThisExchange_Accepted(t *testing.T) {
	h := newTestHarness(t)
	txID, billingID := executeTransactionFor(t, h, 100)

	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-mp-ok", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})))
	if err != nil {
		t.Fatalf("a report naming this Exchange must be accepted, got: %v", err)
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
		return connect.NewRequest(newUsageReport("r-dup", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100}))
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

	if _, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-first", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100}))); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-second-different-id", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100})))
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
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-bad", txID, billingID, &rampv1.Usage{ConsumedQuantity: 200})))
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")

	// Second call — corrected.
	if _, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-good", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100}))); err != nil {
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

	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-free-empty", txID, "", &rampv1.Usage{ConsumedQuantity: 0})))
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

	_, err = h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-free-forged", txID, "forged-handle", &rampv1.Usage{ConsumedQuantity: 0})))
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

	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-free-req-empty", txID, "", &rampv1.Usage{ConsumedQuantity: 0})))
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

	_, err = h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-free-req-forged", txID, "forged-handle", &rampv1.Usage{ConsumedQuantity: 0})))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertReportRejectionField(t, err, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_BILLING_ID")
}

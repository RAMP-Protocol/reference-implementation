//go:build integration

package transport_test

// Recovery from a missed reporting window, driven through the public RPCs.
//
// The defect these cover: a report filed after its deadline was rejected, and a
// rejection leaves the obligation PENDING, which is exactly what the execute
// gate refuses on. An agent that missed one window could neither report nor
// transact, and the only way out was editing the deadline in the database.
//
// Every test here moves a DeterministicClock instead of back-dating a row, so
// nothing reaches past the RPC surface to arrange state.

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestReportUsage_LateReport_UnblocksExecute is the whole recovery path in one
// test: execute, miss the window, get refused, file the late report, execute
// again and succeed.
//
// Each leg goes through the public RPC it belongs to, and the only thing that
// changes between the refused execute and the successful one is the report the
// agent filed. Before this branch the third leg was unreachable: the report was
// rejected for lateness, the obligation stayed PENDING, and the agent stayed
// blocked forever.
func TestReportUsage_LateReport_UnblocksExecute(t *testing.T) {
	h, _, _, det := newReportingHarness(t)

	first := executeOne(t, h, "tx-first", 1)

	// The agent goes quiet past its deadline.
	det.Advance(pastReportingWindow)

	// One overdue out of one due is 100%, so the next transaction is refused.
	blocked, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-blocked")
	assertItemDenied(t, blocked, err, rampv1.DenialReason_DENIAL_REASON_REPORTING_OVERDUE)

	// The remedy: file the report. Late is fine.
	if got := reportFor(t, h, "r-late", first, 1); got == "" {
		t.Error("accepted late report returned no report_id")
	}
	assertObligationState(t, h, first.GetTransactionId(), "RECEIVED", "VALIDATED")
	// Lateness is no longer marked with an outcome of its own, so the row has to
	// carry it: fulfilled_at after window_end is the whole record that this
	// report arrived past its deadline. Both come from the service clock, which
	// is what makes the comparison mean anything.
	assertReportFiledLate(t, h, first.GetTransactionId())

	// Same agent, same tenant, nothing else changed — and it goes through.
	executeOne(t, h, "tx-after", 1)
}

// TestReportUsage_RejectedRetrySameKey_Revalidates proves a rejected report does
// not consume its idempotency key.
//
// A rejection persists source_report_id, so a retry carrying the same key used
// to match the replay probe: it returned 200 with an empty report_id, never
// re-validated, and left the obligation PENDING while the agent believed it had
// reported. Our own MCP tool tells agents to reuse the key when retrying, so
// that was the likely recovery path, and it would have defeated the acceptance
// of late reports entirely. The probe now fires only on a prior ACCEPTED result.
func TestReportUsage_RejectedRetrySameKey_Revalidates(t *testing.T) {
	h, _, _, det := newReportingHarness(t)

	item := executeOne(t, h, "tx-retry", 100)
	det.Advance(pastReportingWindow)

	const key = "r-same-key"

	// First attempt: outside the ±20% tolerance, so rejected.
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport(
		key, item.GetTransactionId(), item.GetBillingId(), &rampv1.Usage{ConsumedQuantity: 500},
	)))
	assertConnectError(t, err, connect.CodeInvalidArgument, "outside")
	assertObligationState(t, h, item.GetTransactionId(), "PENDING", "REJECTED_TOLERANCE")

	// Retry under the SAME key with corrected data. A replay short-circuit here
	// would return 200 with an empty report_id and leave the obligation PENDING.
	reportID := reportFor(t, h, key, item, 100)
	if reportID == "" {
		t.Fatal("corrected retry returned an empty report_id: the replay probe " +
			"short-circuited a key that was only ever rejected")
	}
	assertObligationState(t, h, item.GetTransactionId(), "RECEIVED", "VALIDATED")

	// And the agent is actually unblocked, which is the point of the whole fix.
	executeOne(t, h, "tx-after-retry", 1)
}

// TestReportUsage_AcceptedReplay_SkipsValidation pins the other half of the
// probe: an ACCEPTED key still short-circuits, and still without re-validating.
//
// The replayed report carries a consumed quantity far outside tolerance. If the
// probe had been narrowed into uselessness, that payload would be validated and
// rejected; instead the original report_id comes back unchanged. This is the
// test that fails if the issued_report_id predicate is over-applied.
func TestReportUsage_AcceptedReplay_SkipsValidation(t *testing.T) {
	h, _, _, _ := newReportingHarness(t)

	item := executeOne(t, h, "tx-replay", 100)
	const key = "r-accepted"
	first := reportFor(t, h, key, item, 100)

	// The clock never moves here, so this report is the on-time mirror of the
	// late leg above. The pair is what pins the direction of the comparison: one
	// records fulfilled_at before window_end and the other after, and no constant
	// offset satisfies both. Taking either timestamp from the database clock
	// while the deadline comes from the injected one breaks exactly one of them.
	assertReportFiledOnTime(t, h, item.GetTransactionId())

	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport(
		key, item.GetTransactionId(), item.GetBillingId(), &rampv1.Usage{ConsumedQuantity: 9_999},
	)))
	if err != nil {
		t.Fatalf("replay of an accepted report must succeed, got: %v", err)
	}
	if got := resp.Msg.GetReportId(); got != first {
		t.Errorf("replay returned report_id %q, want the original %q", got, first)
	}
	// Unchanged: the replay wrote nothing and validated nothing.
	assertObligationState(t, h, item.GetTransactionId(), "RECEIVED", "VALIDATED")
}

// TestReportUsage_RejectedAfterAccepted_LeavesTheAcceptedRowIntact proves a
// second, invalid report cannot rewrite a settled obligation.
//
// The rejection statement records an outcome against a PENDING obligation. With
// no state predicate it matched any row, so an agent whose report had already
// been accepted could file a deliberately invalid one under a new key and walk
// the outcome back from VALIDATED to a rejection — destroying the record that a
// conformant report was filed, on the surface a dispute would be settled from.
// It also moved source_report_id onto the new key, so replaying the accepted key
// no longer found it and the agent was told its own accepted report was a
// duplicate.
//
// The agent is the party a dispute runs against, so it must not be able to edit
// the trail.
func TestReportUsage_RejectedAfterAccepted_LeavesTheAcceptedRowIntact(t *testing.T) {
	h, _, logs, _ := newReportingHarness(t)

	item := executeOne(t, h, "tx-settled", 100)
	const acceptedKey = "r-accepted-first"
	reportID := reportFor(t, h, acceptedKey, item, 100)

	// A second report under a DIFFERENT key, far outside tolerance. It is
	// refused for being against an obligation that is already reported, not for
	// the tolerance breach: the state is checked when the rejection is written,
	// so the settled row is never touched.
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport(
		"r-second-key", item.GetTransactionId(), item.GetBillingId(),
		&rampv1.Usage{ConsumedQuantity: 9_999},
	)))
	assertConnectError(t, err, connect.CodeFailedPrecondition, "already reported")

	// The refusal writes nothing to the obligation row and rolls its transaction
	// back, so this log line is the only record that the attempt happened. An
	// operator settling a dispute has nothing else to read, which is why the
	// line is asserted here rather than left to the handler's error alone.
	assertLogContains(t, logs,
		`"outcome":"REJECTED_ALREADY_REPORTED"`,
		`"agent_id":"agent-test"`,
		`"tenant_id":"`+h.tenantID+`"`,
		`"transaction_id":"`+item.GetTransactionId()+`"`,
	)

	// The accepted outcome survived.
	assertObligationState(t, h, item.GetTransactionId(), "RECEIVED", "VALIDATED")

	// And the accepted key still replays to the original report id, which is the
	// guarantee the overwrite used to break.
	resp, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport(
		acceptedKey, item.GetTransactionId(), item.GetBillingId(),
		&rampv1.Usage{ConsumedQuantity: 100},
	)))
	if err != nil {
		t.Fatalf("replay of the accepted key must still succeed, got: %v", err)
	}
	if got := resp.Msg.GetReportId(); got != reportID {
		t.Errorf("replay returned report_id %q, want the original %q", got, reportID)
	}
}

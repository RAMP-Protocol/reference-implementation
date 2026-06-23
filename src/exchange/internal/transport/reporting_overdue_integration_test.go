//go:build integration

package transport_test

import (
	"strings"
	"testing"

	connect "connectrpc.com/connect"
)

// TestExecuteTransaction_ReportingOverdue_Denied proves the REPORTING_OVERDUE
// gate: an agent holding a PENDING reporting obligation past its deadline is
// refused on its next transaction with FailedPrecondition, the denial is
// attributed to the right (tenant, agent) in the structured audit log, and —
// because the gate runs before billing — no funds are reserved for the refused
// transaction. The overdue state is seeded directly — a real execute creates the
// FK-valid transaction_log row + PENDING obligation, then its deadline is
// back-dated. (The broker, which auto-reports and would clear the obligation,
// never runs in this exchange-only harness, so the obligation stays PENDING.)
func TestExecuteTransaction_ReportingOverdue_Denied(t *testing.T) {
	h, rec, logs := newRecordingHarnessCapturingLogs(t)

	seed, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-seed")
	if err != nil {
		t.Fatalf("seed execute: %v", err)
	}
	h.backdateObligationDeadline(t, seed.Msg.GetTransactionId())

	_, err = executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-gated")
	assertConnectError(t, err, connect.CodeFailedPrecondition, "reporting overdue")

	// The audit record must prove WHO was denied, not just THAT a denial
	// happened — a cross-tenant/agent mis-attribution must fail this test.
	got := logs.String()
	for _, want := range []string{
		`"outcome":"REJECTED_REPORTING_OVERDUE"`,
		`"agent_id":"agent-test"`,
		`"tenant_id":"` + h.tenantID + `"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("audit log missing %s; got: %s", want, got)
		}
	}

	// The gate runs before resolveBilling, so the denied tx reserves no funds.
	// The only Authorize must be the seed; if "tx-gated" authorized, a reorder
	// past billing has leaked a hold.
	if key, _ := rec.lastAuthorizeKey(); key != "tx-seed" {
		t.Errorf("gated tx reserved funds: last Authorize key = %q, want %q", key, "tx-seed")
	}
}

// TestExecuteTransaction_NoOverdue_Proceeds proves the gate fires only on a
// past deadline, not on the mere existence of a PENDING obligation: the first
// transaction leaves a PENDING obligation with a future deadline, and the next
// transaction for the same agent still succeeds.
func TestExecuteTransaction_NoOverdue_Proceeds(t *testing.T) {
	h := newTestHarness(t)

	first, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-1")
	if err != nil {
		t.Fatalf("first execute: %v", err)
	}
	// Discriminator: the first tx must leave a *live* PENDING obligation. If it
	// did not, the second execute would trivially pass and prove nothing.
	assertObligationPending(t, h, first.Msg.GetTransactionId())

	resp, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-2")
	if err != nil {
		t.Fatalf("second execute denied unexpectedly: %v", err)
	}
	if resp.Msg.GetTransactionId() == "" {
		t.Fatalf("second execute returned empty transaction id")
	}
}

// TestExecuteTransaction_ReportingOverdueQueryError_FailsClosed proves the gate
// fails CLOSED: when the outstanding-obligations query errors, the transaction
// is refused with Internal — never allowed through. Renaming the table makes the
// gate's ListOutstandingObligations (the first reporting_obligations access in
// the execute path) error, exercising the branch a fail-open regression would
// skip.
func TestExecuteTransaction_ReportingOverdueQueryError_FailsClosed(t *testing.T) {
	h := newTestHarness(t)

	// Stage a real, valid offer first so the request reaches the gate before any
	// persist; pushDiscoverOffer does not touch reporting_obligations.
	offer := pushDiscoverOffer(t, h, 1)

	if _, err := h.pool.Exec(h.ctx,
		`ALTER TABLE ramp.reporting_obligations RENAME TO reporting_obligations_quarantined`); err != nil {
		t.Fatalf("rename obligations table: %v", err)
	}

	_, err := executeOfferRawWithID(t, h, offer, "tx-query-err")
	// CodeInternal pins fail-closed; the gate-specific message distinguishes it
	// from any other internal error in the path.
	assertConnectError(t, err, connect.CodeInternal, "list outstanding obligations")
}

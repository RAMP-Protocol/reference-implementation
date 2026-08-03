//go:build integration

package transport_test

import (
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

func mustBillingAmount(t *testing.T, raw, ccy string) billing.Amount {
	t.Helper()
	a, err := billing.NewAmount(raw, ccy)
	if err != nil {
		t.Fatalf("NewAmount: %v", err)
	}
	return a
}

// stringPtr returns a pointer to s (generic proto optional-string helper).
func stringPtr(s string) *string { return &s }

// tenantDrain returns an authorize request that subtracts the full seed balance
// so subsequent authorizations fail. billingRef is the account to drain — the ref
// the harness registered the caller under, not the agent id.
func tenantDrain(t *testing.T, billingRef string) billing.AuthorizeRequest {
	t.Helper()
	return billing.AuthorizeRequest{
		TenantID: "t", BillingRef: billingRef,
		UnitCost: mustBillingAmount(t, "10.00", "USD"),
		Quantity: 1, Unit: "access",
	}
}

// assertObligationPending asserts the most-recent obligation for txID is PENDING
// with a deadline still in the future — the live precondition the no-overdue
// gate path depends on (a PENDING-but-not-yet-due obligation must NOT block the
// agent's next transaction).
func assertObligationPending(t *testing.T, h *testHarness, txID string) {
	t.Helper()
	ob, err := h.queries.GetObligationByTransaction(h.ctx, txID)
	if err != nil {
		t.Fatalf("GetObligationByTransaction(%s): %v", txID, err)
	}
	if ob.State != sqlc.RampObligationStatePENDING {
		t.Errorf("state = %q, want PENDING", ob.State)
	}
	if !ob.Deadline.Valid {
		t.Fatalf("deadline not set on obligation for %s", txID)
	}
	if !ob.Deadline.Time.After(time.Now()) {
		t.Errorf("deadline %s not in the future", ob.Deadline.Time)
	}
}

// backdateObligationDeadline moves the deadline of the obligation for the given
// (persisted) transaction id one hour into the past, driving the
// ListOutstandingObligations `deadline < NOW()` predicate. NOW() is Postgres
// server time — the injected service clock does not move it — so a raw UPDATE is
// the correct, minimal lever for making a live obligation overdue (the only one
// that does not wait out the reporting window).
func (h *testHarness) backdateObligationDeadline(t *testing.T, transactionID string) {
	t.Helper()
	if _, err := h.pool.Exec(h.ctx,
		`UPDATE ramp.reporting_obligations SET deadline = NOW() - INTERVAL '1 hour' WHERE transaction_id = $1`,
		transactionID); err != nil {
		t.Fatalf("back-date obligation deadline: %v", err)
	}
}

//go:build integration

package transport_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"

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

// ceAs is a thin errors.As wrapper for *connect.Error to keep test ergonomics
// compact.
func ceAs(err error, target **connect.Error) bool {
	var ce *connect.Error
	if err == nil {
		return false
	}
	ok := errors.As(err, &ce)
	if ok {
		*target = ce
	}
	return ok
}

// tenantDrain returns an authorize request that subtracts the full seed
// balance so subsequent authorizations fail.
func tenantDrain(t *testing.T) billing.AuthorizeRequest {
	t.Helper()
	return billing.AuthorizeRequest{
		TenantID: "t", AgentID: "agent-test",
		UnitCost: mustBillingAmount(t, "10.00", "USD"),
		Quantity: 1, Unit: "access",
	}
}

// assertConnectCode fails the test unless err is a *connect.Error whose Code
// equals want. The error MUST be non-nil. Consolidated here so every
// transport-layer integration test asserts Connect codes with the same shape.
func assertConnectCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *connect.Error
	if !ceAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	if ce.Code() != want {
		t.Fatalf("code = %v (msg %q), want %v", ce.Code(), ce.Message(), want)
	}
}

// assertConnectError combines assertConnectCode with a substring check on
// the error message. Used to pin the textual field-name detail produced by
// the validator.
func assertConnectError(t *testing.T, err error, want connect.Code, wantInMsg string) {
	t.Helper()
	assertConnectCode(t, err, want)
	var ce *connect.Error
	_ = ceAs(err, &ce)
	if wantInMsg != "" && !strings.Contains(ce.Message(), wantInMsg) {
		t.Errorf("message %q does not contain %q", ce.Message(), wantInMsg)
	}
}

// assertObligationState asserts the (state, validation_outcome) pair on the
// most-recent obligation for the given transaction. validated_at MUST be
// populated whenever wantOutcome is non-empty (every
// validation attempt stamps the audit timestamp).
func assertObligationState(t *testing.T, h *testHarness, txID string, wantState, wantOutcome string) {
	t.Helper()
	ob, err := h.queries.GetObligationByTransaction(h.ctx, txID)
	if err != nil {
		t.Fatalf("GetObligationByTransaction: %v", err)
	}
	if string(ob.State) != wantState {
		t.Errorf("state = %q, want %q", ob.State, wantState)
	}
	gotOutcome := ""
	if ob.ValidationOutcome.Valid {
		gotOutcome = string(ob.ValidationOutcome.RampValidationOutcome)
	}
	if gotOutcome != wantOutcome {
		t.Errorf("validation_outcome = %q, want %q", gotOutcome, wantOutcome)
	}
	if wantOutcome != "" && !ob.ValidatedAt.Valid {
		t.Errorf("validated_at not set; expected timestamp for outcome %q", wantOutcome)
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

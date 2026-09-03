//go:build integration

package transport_test

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
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

// obligationView reads a transaction's reporting obligation through the operator
// evidence RPC — the public surface an obligation is normally read through, and
// the tier-1 surface the Testing Doctrine asks for. Returns nil when the
// transaction minted no obligation, which is what the route renders for one.
func obligationView(t *testing.T, h *testHarness, txID string) *evidenceview.ObligationState {
	t.Helper()
	return readEvidence(t, h, h.adminBaseURL(t), txID).ObligationState
}

// mustObligationView reads the obligation through the evidence RPC and fails
// when the transaction minted none. Every assertion about an obligation's
// contents starts here; only assertNoObligation wants the nil case.
func mustObligationView(t *testing.T, h *testHarness, txID string) *evidenceview.ObligationState {
	t.Helper()
	ob := obligationView(t, h, txID)
	if ob == nil {
		t.Fatalf("transaction %s minted no obligation", txID)
	}
	return ob
}

// mustFulfilledObligation is mustObligationView plus the guard the two lateness
// assertions share: an accepted report must have stamped fulfilled_at, or the
// comparison below would be reading a nil pointer rather than a timestamp.
func mustFulfilledObligation(t *testing.T, h *testHarness, txID string) *evidenceview.ObligationState {
	t.Helper()
	ob := mustObligationView(t, h, txID)
	if ob.FulfilledAt == nil {
		t.Fatalf("obligation for %s carries no fulfilled_at after an accepted report", txID)
	}
	return ob
}

// assertObligationPending asserts the obligation for txID is PENDING with a
// deadline still ahead of the service clock — the live precondition the
// no-overdue gate path depends on (a PENDING-but-not-yet-due obligation must NOT
// block the agent's next transaction).
//
// The deadline is compared against the harness clock rather than the wall clock,
// because it was written from the service clock and a test may have moved it.
func assertObligationPending(t *testing.T, h *testHarness, txID string) {
	t.Helper()
	ob := mustObligationView(t, h, txID)
	if got, want := ob.State, "PENDING"; got != want {
		t.Errorf("state = %q, want %q", got, want)
	}
	if ob.WindowEnd.IsZero() {
		t.Fatalf("window_end not set on obligation for %s", txID)
	}
	if !ob.WindowEnd.After(h.now()) {
		t.Errorf("window_end %s is not after the service clock's %s", ob.WindowEnd, h.now())
	}
}

// assertNoObligation asserts the transaction minted no reporting obligation at
// all — the shape a price whose metering is NONE produces. Distinct from
// assertObligationPending: "no row" and "a row nobody has reported yet" are
// different claims, and only the first frees the agent from the execute gate.
//
// Asserted through the evidence RPC, which omits obligation_state entirely when
// there is no obligation, so this drives the handler's nil branch as well.
func assertNoObligation(t *testing.T, h *testHarness, txID string) {
	t.Helper()
	if ob := obligationView(t, h, txID); ob != nil {
		t.Fatalf("transaction %s minted an obligation in state %q; want none", txID, ob.State)
	}
}

// assertReportFiledLate asserts the accepted report was recorded as arriving
// AFTER its deadline. This is what makes lateness derivable rather than marked:
// the Exchange no longer stamps an outcome saying a report was late, so
// fulfilled_at against window_end is the only thing that carries it, and both
// are written from the service clock so the comparison is sound.
//
// It is the assertion that fails if either timestamp is taken from the database
// clock instead: under a moved deterministic clock a NOW() fulfilled_at lands
// roughly a day BEFORE the window_end the service clock wrote.
func assertReportFiledLate(t *testing.T, h *testHarness, txID string) {
	t.Helper()
	ob := mustFulfilledObligation(t, h, txID)
	if !ob.FulfilledAt.After(ob.WindowEnd) {
		t.Errorf("fulfilled_at %s is not after window_end %s: a report filed past the "+
			"deadline was recorded as on time, so one of the two came from the database clock",
			ob.FulfilledAt, ob.WindowEnd)
	}
}

// assertReportFiledOnTime is the mirror of assertReportFiledLate. The pair is
// what pins the comparison: a single-direction assertion is satisfied by a fixed
// offset in either direction, and only one of these two can be.
func assertReportFiledOnTime(t *testing.T, h *testHarness, txID string) {
	t.Helper()
	ob := mustFulfilledObligation(t, h, txID)
	if !ob.FulfilledAt.Before(ob.WindowEnd) {
		t.Errorf("fulfilled_at %s is not before window_end %s: a report filed inside "+
			"the window was recorded as late", ob.FulfilledAt, ob.WindowEnd)
	}
}

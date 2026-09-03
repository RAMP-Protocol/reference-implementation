//go:build integration

package transport_test

import (
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestExecuteTransaction_ReportingOverdue_Denied proves the reporting-overdue
// gate. An agent whose only due obligation is unreported is at 100%, which is
// above the rate ceiling, so its next transaction is refused. The refusal
// arrives as an in-body per-item denial carrying DENIAL_REASON_REPORTING_OVERDUE
// -- the shape every denial-map kind takes after the items-only collapse -- it
// is attributed to the right (tenant, agent) in the audit log, and because the
// gate runs before billing, no funds are reserved.
//
// The obligation is made overdue by moving the service clock past its deadline,
// which is the same clock the gate compares against. No raw SQL is involved: the
// seed transaction is a real execute through the public RPC, and nothing but the
// clock changes between the two calls. (The broker, which auto-reports and would
// clear the obligation, never runs in this exchange-only harness, so the
// obligation stays PENDING.)
func TestExecuteTransaction_ReportingOverdue_Denied(t *testing.T) {
	h, rec, logs, det := newReportingHarness(t)

	if _, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-seed"); err != nil {
		t.Fatalf("seed execute: %v", err)
	}

	det.Advance(pastReportingWindow)

	// Discovered AFTER the advance so the offer's own TTL is still ahead of the
	// service clock — this test is about the reporting gate, not offer expiry.
	resp, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-gated")
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_REPORTING_OVERDUE)

	// The audit record must prove WHO was denied, not just THAT a denial
	// happened — a cross-tenant/agent mis-attribution must fail this test.
	//
	// It must also prove WHAT the refusal was and what it told the operator.
	// The denial reason above is the only thing the agent receives; the kind
	// string and the message travel no further than this line, so if they are
	// not asserted here they are not asserted anywhere. Dropping the kind from
	// the error type's string table would silently turn every one of these
	// lines into "kind":"unspecified".
	//
	// Both counts are pinned: one unreported, one past its deadline.
	assertLogContains(t, logs,
		`"outcome":"REJECTED_REPORTING_OVERDUE"`,
		`"agent_id":"agent-test"`,
		`"tenant_id":"`+h.tenantID+`"`,
		`"kind":"reporting_overdue"`,
		`reporting overdue: 1 unreported, out of 1 past their deadline`,
		`file the missing usage reports`,
	)

	// The gate runs before resolveBilling, so the denied tx reserves no funds.
	// The only Authorize must be the seed's; if "tx-gated" authorized, a reorder
	// past billing has leaked a hold. Items-only billing keys on the DERIVED
	// per-item key (idempotency_key:offer_id), so the seed's Authorize key is
	// prefixed "tx-seed:" — assert the last Authorize is the seed's, not "tx-gated".
	if key, _ := rec.lastAuthorizeKey(); !strings.HasPrefix(key, "tx-seed") {
		t.Errorf("gated tx reserved funds: last Authorize key = %q, want prefix %q", key, "tx-seed")
	}
}

// TestExecuteTransaction_Overdue_ScopedToTheAgent proves the compliance count is
// scoped by agent, not only by tenant.
//
// The gate's count query filters on both tenant_id and agent_id. The batch test
// covers the tenant half — an item for a tenant the agent owes nothing to comes
// back delivered. This covers the agent half: a delinquent agent and an innocent
// one share a tenant, and only the delinquent one is refused.
//
// Without this, deleting the agent_id predicate leaves every reporting test
// passing while one agent's missed report blocks every other agent on the same
// publisher — the deadlock this branch removes, spread to agents that never
// missed anything.
func TestExecuteTransaction_Overdue_ScopedToTheAgent(t *testing.T) {
	h, _, _, det := newReportingHarness(t)

	if _, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-delinquent"); err != nil {
		t.Fatalf("seed execute for the delinquent agent: %v", err)
	}
	det.Advance(pastReportingWindow)

	// Discriminator: the agent that missed its window is refused, so the gate is
	// live for this tenant. Without this leg a scoping bug that disabled the
	// gate entirely would also pass the assertion below.
	denied, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-delinquent-again")
	assertItemDenied(t, denied, err, rampv1.DenialReason_DENIAL_REASON_REPORTING_OVERDUE)

	// A second agent on the SAME tenant, with no obligations at all: nothing of
	// its own is overdue, so it must be delivered.
	innocent := h.addExecuteCaller(t, "agent-innocent")
	resp, err := executeSingleItemAs(t, h, innocent, "tx-innocent", pushDiscoverOffer(t, h, 1))
	if err != nil {
		t.Fatalf("an agent with no obligations was refused outright: %v", err)
	}
	item := singleResultItem(t, resp)
	if item.GetRetrievalEndpoint() == "" {
		t.Fatalf("an agent with no obligations was denied: %v", item.GetDenialReason())
	}
}

// TestExecuteTransaction_NoOverdue_Proceeds proves the gate fires on a passed
// deadline, not on the mere existence of a PENDING obligation: the first
// transaction leaves a PENDING obligation still inside its window, and the next
// transaction for the same agent succeeds.
func TestExecuteTransaction_NoOverdue_Proceeds(t *testing.T) {
	h := newTestHarness(t)

	first, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-1")
	if err != nil {
		t.Fatalf("first execute: %v", err)
	}
	// Discriminator: the first tx must leave a *live* PENDING obligation. If it
	// did not, the second execute would trivially pass and prove nothing.
	assertObligationPending(t, h, singleResultItem(t, first).GetTransactionId())

	resp, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-2")
	if err != nil {
		t.Fatalf("second execute denied unexpectedly: %v", err)
	}
	if singleResultItem(t, resp).GetTransactionId() == "" {
		t.Fatalf("second execute returned empty transaction id")
	}
}

// TestExecuteTransaction_ReportingOverdueQueryError_FailsClosed proves the gate
// fails CLOSED: when the compliance-count query errors, the transaction is
// refused with Internal — never allowed through, and never softened into an
// in-body denial either, because KindInternal carries no wire reason and so
// still aborts the whole batch. Renaming the table makes the gate's count query
// (the first reporting_obligations access in the execute path) error, exercising
// the branch a fail-open regression would skip.
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
	assertConnectError(t, err, connect.CodeInternal, "count reporting obligations")
}

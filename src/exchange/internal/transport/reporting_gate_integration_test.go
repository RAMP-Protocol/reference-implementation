//go:build integration

package transport_test

// The reporting-overdue gate's policy, and the obligation terms the agent is
// told about, driven through the public RPCs.
//
// The gate refuses when more than 10 obligations are overdue, or when more than
// one in five due obligations is unreported. Overdue means still PENDING with
// its deadline passed, so a reported obligation never counts again however late
// the report was. The denominator is every obligation whose deadline has passed.
//
// The absolute cap is not exercised here: reaching 11 overdue while staying
// under the rate needs 55 obligations. The arithmetic for it is pinned in
// TestOverdueRule_Blocks in the service package; what these tests cover is the
// rate boundary the acceptance criteria name, through the real RPC.

import (
	"strconv"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// seedMeteringNoneTerm is a priced term whose pricing meters nothing: a one-time
// perpetual sale. billing_id is issued at ExecuteTransaction and the ledger entry
// closes there, so no usage report is owed and no obligation is minted. Every
// other field matches seedPricedTermEst, so a test that swaps this in changes one
// axis only.
func seedMeteringNoneTerm() *rampv1.LicenseTerm {
	term := seedPricedTermEst(1)
	metering := rampv1.PricingMetering_PRICING_METERING_NONE
	term.Pricing.Metering = &metering
	return term
}

// TestExecuteTransaction_OverdueRate_Boundary walks the rate ceiling through the
// public RPCs: 2 unreported out of 10 due is exactly 20% and passes, 3 out of 10
// is 30% and is refused.
//
// Each case executes ten transactions, reports some of them, then moves the
// clock past every deadline so the ten become the denominator and the unreported
// ones become overdue.
func TestExecuteTransaction_OverdueRate_Boundary(t *testing.T) {
	const due = 10

	cases := []struct {
		name        string
		overdue     int
		wantBlocked bool
	}{
		{name: "TwoOfTen_Allowed", overdue: 2, wantBlocked: false},
		{name: "ThreeOfTen_Blocked", overdue: 3, wantBlocked: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A harness per case: each acquires the shared database and resets it
			// to the migrated baseline, so the two histories cannot bleed.
			h, _, _, det := newReportingHarness(t)

			items := make([]*rampv1.TransactionResultItem, 0, due)
			for i := range due {
				items = append(items, executeOne(t, h, "tx-"+strconv.Itoa(i), 1))
			}
			// Report all but the ones meant to lapse. Reporting before the advance
			// keeps this leg about the rate, not about lateness.
			for i, item := range items[tc.overdue:] {
				reportFor(t, h, "r-"+strconv.Itoa(i), item, 1)
			}

			det.Advance(pastReportingWindow)

			if tc.wantBlocked {
				resp, err := executeOfferRawWithID(t, h, pushDiscoverOffer(t, h, 1), "tx-probe")
				assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_REPORTING_OVERDUE)
				return
			}
			// executeOne owns the allowed leg: it fails on a transport error and
			// on an in-body denial under HTTP 200, and prints the denial reason.
			// Repeating those checks here is how the two drift apart.
			executeOne(t, h, "tx-probe", 1)
		})
	}
}

// TestExecuteTransaction_AllReportedSomeLate_NotBlocked proves lateness alone
// never blocks. Three obligations all pass their deadline unreported, all three
// are then reported late, and the next transaction goes through: overdue counts
// obligations still PENDING, so a report clears one whatever time it arrives.
func TestExecuteTransaction_AllReportedSomeLate_NotBlocked(t *testing.T) {
	h, _, _, det := newReportingHarness(t)

	items := []*rampv1.TransactionResultItem{
		executeOne(t, h, "tx-a", 1),
		executeOne(t, h, "tx-b", 1),
		executeOne(t, h, "tx-c", 1),
	}

	det.Advance(pastReportingWindow)

	for i, item := range items {
		reportFor(t, h, "r-late-"+strconv.Itoa(i), item, 1)
	}

	// 0 overdue of 3 due. Every report was late, and none of them counts.
	executeOne(t, h, "tx-after-late-reports", 1)
}

// TestExecuteTransaction_Batch_OverdueDeniesItemsAndContinues proves the gate no
// longer kills a whole batch.
//
// The refusal used to carry a kind with no wire reason, so the batch loop could
// not classify it as a per-item denial and aborted the entire request: one
// overdue obligation destroyed every item, including ones for tenants the agent
// was perfectly current with. Both halves of that are asserted here, because
// only the second one is the fix — "no error" would also be true of a loop that
// denied everything.
//
// The batch carries three items: two for the tenant the agent is behind on, and
// one for a tenant it has never transacted with, so it owes that tenant nothing.
// The first two come back denied in-body under HTTP 200, and the third comes back
// delivered.
func TestExecuteTransaction_Batch_OverdueDeniesItemsAndContinues(t *testing.T) {
	h, _, _, det := newReportingHarness(t)

	executeOne(t, h, "tx-seed-batch", 1)
	det.Advance(pastReportingWindow)

	first := pushDiscoverOffer(t, h, 1)
	second := pushDiscoverTermOffer(t, h, "/articles/second", seedPricedTermEst(1))
	// A second publisher the agent is current with: no obligations at all for
	// this (tenant, agent), so nothing is overdue and the gate has no reason to
	// refuse. addTenant seeds the row and its signing key, which the offer for
	// this domain is signed with.
	otherTenantID, _ := h.addTenant(t, "current-publisher", "agent-current-publisher")
	third := pushDiscoverTermOfferForTenant(
		t, h, otherTenantID, "current-publisher.example", "/articles/third", seedPricedTermEst(1))

	const reqKey = "tx-batch-overdue"
	requester := newRequester("agent-test", "agent.example")
	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(&rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: reqKey,
		Requester:      requester,
		Items: []*rampv1.TransactionItem{
			{Offer: first, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, first, requester, reqKey)},
			{Offer: second, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, second, requester, reqKey)},
			{Offer: third, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, third, requester, reqKey)},
		},
	}))
	if err != nil {
		t.Fatalf("an overdue agent's batch must return in-body denials, not abort: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 3 {
		t.Fatalf("batch returned %d items, want 3 — the loop aborted instead of continuing", len(items))
	}
	for i, item := range items[:2] {
		if got := item.GetDenialReason(); got != rampv1.DenialReason_DENIAL_REASON_REPORTING_OVERDUE {
			t.Errorf("item %d denial_reason = %v, want DENIAL_REASON_REPORTING_OVERDUE", i, got)
		}
		if item.GetRetrievalEndpoint() != "" {
			t.Errorf("item %d was denied but still carries a retrieval_endpoint", i)
		}
	}
	// The item that makes this test about "continues" rather than "does not
	// error": a tenant the agent owes nothing is delivered in the same response.
	survivor := items[2]
	if got := survivor.GetDenialReason(); got != rampv1.DenialReason_DENIAL_REASON_UNSPECIFIED {
		t.Errorf("the unaffected tenant's item was denied with %v; the gate is per "+
			"(tenant, agent) and this agent owes that tenant nothing", got)
	}
	if survivor.GetRetrievalEndpoint() == "" {
		t.Error("the unaffected tenant's item carries no retrieval_endpoint: the batch " +
			"denied every item instead of only the affected ones")
	}
}

// TestExecuteTransaction_MeteringNone_MintsNoObligation proves the metering
// carve-out end to end: a term whose pricing is PRICING_METERING_NONE is pushed
// through the catalog RPC, executed, and owes nothing.
//
// Three separate claims, because "required: false" on the wire would be a lie if
// a row were still written, and a written row would block the agent later:
// the delivered item says no report is required, no obligation row exists, and a
// later transaction is not gated on account of it.
func TestExecuteTransaction_MeteringNone_MintsNoObligation(t *testing.T) {
	h, _, _, det := newReportingHarness(t)

	offer := pushDiscoverTermOffer(t, h, "/articles/perpetual", seedMeteringNoneTerm())
	resp, err := executeOfferRawWithID(t, h, offer, "tx-perpetual")
	if err != nil {
		t.Fatalf("execute a metering-NONE term: %v", err)
	}
	item := singleResultItem(t, resp)

	obligation := item.GetReportingObligation()
	if obligation == nil {
		t.Fatal("result carried no reporting_obligation block at all")
	}
	if obligation.GetRequired() {
		t.Error("reporting_obligation.required = true for a term that meters nothing")
	}
	assertNoObligation(t, h, item.GetTransactionId())

	// A report against a transaction that minted no obligation is refused with
	// NotFound. This is a state only the metering carve-out makes reachable —
	// the transaction exists and the caller owns it, but there is no obligation
	// to report against. The unknown-transaction test covers a transaction id
	// that does not exist at all; both answers come from the same join today, so
	// without this leg splitting that lookup would change the wire behavior for
	// a perpetual sale and leave every test passing.
	_, err = h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport(
		"r-perpetual", item.GetTransactionId(), item.GetBillingId(),
		&rampv1.Usage{ConsumedQuantity: 1},
	)))
	assertConnectError(t, err, connect.CodeNotFound, "no obligation for transaction")

	// Well past any window that would have applied. Nothing was minted, so
	// nothing can be overdue.
	det.Advance(pastReportingWindow)
	executeOne(t, h, "tx-after-perpetual", 1)
}

// TestExecuteTransaction_ResultCarriesObligationTerms proves the agent is told
// what it will actually be held to.
//
// The result used to report required=true with no window and no field list,
// while the obligation row carried both — so an agent could not know its
// deadline or which fields its report had to contain. Both now come from the
// same plan the row is written from. The policy is set through the admin RPC, so
// the values under test travel the production write path.
func TestExecuteTransaction_ResultCarriesObligationTerms(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := h.adminSurface(t)

	const windowSeconds = 3600
	window := int32(windowSeconds)
	mustSetPolicy(t, h, admin, &rampadminv1.ReportingPolicy{
		RequiredFields: []string{"transaction_id", "consumed_quantity"},
		WindowSeconds:  &window,
	})

	item := executeOne(t, h, "tx-obligation-terms", 1)
	obligation := item.GetReportingObligation()
	if obligation == nil {
		t.Fatal("result carried no reporting_obligation block at all")
	}
	if !obligation.GetRequired() {
		t.Error("reporting_obligation.required = false for a metered term")
	}
	if got := obligation.GetWindow().GetSeconds(); got != windowSeconds {
		t.Errorf("reporting_obligation.window = %ds, want %ds — the agent cannot "+
			"know its deadline from a window the Exchange did not send", got, windowSeconds)
	}
	want := []string{"transaction_id", "consumed_quantity"}
	got := obligation.GetRequiredFields()
	if len(got) != len(want) {
		t.Fatalf("reporting_obligation.required_fields = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reporting_obligation.required_fields[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// The window the agent was told is the window the deadline was written from.
	// Both come from one plan, one line apart, and nothing else in the suite
	// compares them: every other window_end assertion is self-relative. Take the
	// deadline from a different source and the agent is told one window and
	// counted overdue at another, which is the disagreement the shared plan
	// exists to prevent.
	//
	// The comparison is against the row's own created_at, so it holds whatever
	// the harness clock reads. The two are not written from the same clock —
	// the deadline comes from the service clock and created_at from the
	// database — so they differ by the microseconds between those two reads.
	// The tolerance absorbs that and still catches the failure this guards: a
	// deadline taken from the configured default instead of the advertised
	// window is 24 hours out, not microseconds.
	view := mustObligationView(t, h, item.GetTransactionId())
	span := view.WindowEnd.Sub(view.CreatedAt)
	if drift := (span - windowSeconds*time.Second).Abs(); drift > time.Second {
		t.Errorf("obligation deadline is %s after the execute, but the agent was told %ds",
			span, windowSeconds)
	}

	// The values are not decoration: a report that omits a named field is
	// rejected against this same list.
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport(
		"r-missing-field", item.GetTransactionId(), item.GetBillingId(), nil,
	)))
	assertConnectError(t, err, connect.CodeInvalidArgument, "consumed_quantity")
}

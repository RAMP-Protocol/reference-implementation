package main

import (
	"strings"
	"testing"
)

func TestBuildLedger_rendersTheChainInTheOrderEventsHappened(t *testing.T) {
	l := BuildLedger(newFixture(t).Sources)

	if len(l.Rows) != 7 {
		t.Fatalf("chain has %d rows, want 7", len(l.Rows))
	}
	// Row 6's party follows the delivery outcome, and the fixture's is
	// cdn-origin-fetch: the CDN had not fetched the origin when the edge record
	// was written, so the Edge is the only party that witnessed anything. On the
	// runtimes where the worker awaits the origin's response the party is
	// Origin, which TestBuildLedger_row6ClaimsOnlyWhatTheOutcomeSupports covers.
	wantParties := []string{"Exchange", "Broker", "Agent agents.example", "Exchange", "Edge", "Edge", "Exchange"}
	for i, want := range wantParties {
		if l.Rows[i].Party != want {
			t.Errorf("row %d party = %q, want %q", i+1, l.Rows[i].Party, want)
		}
	}
	if l.TransactionID != fixtureTx || l.TenantID != fixtureTenant {
		t.Errorf("header = %s/%s, want %s/%s", l.TransactionID, l.TenantID, fixtureTx, fixtureTenant)
	}
	for i, row := range l.Rows {
		if row.Absence != "" {
			t.Errorf("row %d reports a gap on a complete chain: %s", i+1, row.Absence)
		}
	}
}

// A row that could not be read must carry its reason and nothing else. Empty
// cells would render as a step that happened and recorded no detail, which is a
// different and much stronger claim than "this was not read".
func TestBuildLedger_absentLegsRenderTheReasonInsteadOfEmptyCells(t *testing.T) {
	s := newFixture(t).Sources
	s.Selection = nil
	s.SelectionAbsence = "not read: no Broker database URL configured"
	s.Delivery = nil
	s.DeliveryAbsence = "no delivery recorded: nothing in CloudWatch yet"

	rows := BuildLedger(s).Rows
	for _, i := range []int{1, 4, 5} {
		row := rows[i]
		if row.Absence == "" {
			t.Errorf("row %d (%s) should report a gap", i+1, row.Party)
		}
		if row.Event != "" || row.Correlator != "" || row.Crypto != "" {
			t.Errorf("row %d (%s) states content next to its gap: %+v", i+1, row.Party, row)
		}
	}
	// The Exchange-side rows are unaffected by the other parties' silence.
	for _, i := range []int{0, 2, 3, 6} {
		if rows[i].Absence != "" {
			t.Errorf("row %d (%s) should be unaffected: %s", i+1, rows[i].Party, rows[i].Absence)
		}
	}
}

// A direct delivery mints no signed URL. Rows 4 and 5 must say that rather than
// print a zero digest or an epoch expiry, both of which would be facts the
// Exchange never stated.
func TestBuildLedger_directDeliveryHasNoSignedURL(t *testing.T) {
	s := newFixture(t).Sources
	s.Transaction.SignedURLHash = nil
	s.Transaction.SignedURLExpiry = nil
	s.Delivery = nil
	s.DeliveryAbsence = "not applicable: this transaction minted no signed URL"

	rows := BuildLedger(s).Rows
	if !strings.Contains(rows[3].Absence, "no signed URL") {
		t.Errorf("row 4 should state there is no URL, got %+v", rows[3])
	}
	if strings.Contains(rows[3].Event, "1970") {
		t.Errorf("row 4 printed an epoch timestamp for an absent expiry: %q", rows[3].Event)
	}
}

// A signed URL with a recorded digest but no recorded expiry reaches the
// expiry render, which the absent-URL case above never does — that case returns
// on the empty digest before the timestamp is touched. This is the only path
// that renders an absent expiry, and it renders a dash.
//
// It is also the case that made stamp take a pointer. The earlier signature was
// stamp(t time.Time, present bool), which every caller wrote as
// stamp(*p, p != nil); Go evaluates both arguments before the body runs, so the
// dereference happened before the guard was read and this input panicked.
func TestBuildLedger_signedURLWithNoRecordedExpiryRendersADash(t *testing.T) {
	s := newFixture(t).Sources
	s.Transaction.SignedURLExpiry = nil

	row := BuildLedger(s).Rows[3]
	if row.Absence != "" {
		t.Fatalf("row 4 should still be a recorded step, got absence %q", row.Absence)
	}
	if !strings.Contains(row.Event, "expiring —") {
		t.Errorf("row 4 should render an absent expiry as a dash, got %q", row.Event)
	}
	if strings.Contains(row.Event, "1970") {
		t.Errorf("row 4 printed an epoch timestamp for an absent expiry: %q", row.Event)
	}
}

// Row 6 may say the origin answered only on the runtimes where the worker
// actually waited for it. On CloudFront the worker runs at viewer-request: it
// writes its record and hands the request back, and the CDN fetches the origin
// afterwards, so no origin response was ever observed. Claiming one there would
// be the chain asserting something no party recorded.
//
// The outcome alone never promotes the row to "content served" — that needs a
// success status too, which the sibling test below covers. The fixture carries
// no status, so every case here must stop at "the origin answered".
func TestBuildLedger_row6ClaimsOnlyWhatTheOutcomeSupports(t *testing.T) {
	for _, tc := range []struct {
		outcome      string
		wantAnswered bool
		wantInEvent  string
	}{
		{"cdn-origin-fetch", false, "no origin response was observed"},
		{"origin-forwarded", true, "the origin answered via"},
		{"same-zone", true, "the origin answered via"},
		// An outcome this tool does not recognize must fall to the weaker
		// claim, so a rename on the worker side can never promote a row.
		{"some-future-outcome", false, "no origin response was observed"},
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			s := newFixture(t).Sources
			s.Delivery.Outcome = tc.outcome

			row := BuildLedger(s).Rows[5]
			answered := strings.Contains(row.Step, "origin response observed")
			if answered != tc.wantAnswered {
				t.Errorf("outcome %q: row 6 step = %q, claims the origin answered = %v, want %v",
					tc.outcome, row.Step, answered, tc.wantAnswered)
			}
			if !strings.Contains(row.Event, tc.wantInEvent) {
				t.Errorf("outcome %q: row 6 event = %q, want it to contain %q",
					tc.outcome, row.Event, tc.wantInEvent)
			}
			if !tc.wantAnswered && row.Party == "Origin" {
				t.Errorf("outcome %q: row 6 names the Origin as the party of a row "+
					"that reports no origin response", tc.outcome)
			}
			// This fixture records no origin status, so no outcome may promote
			// the row to a claim about the content itself.
			if strings.Contains(row.Step, "content served") {
				t.Errorf("outcome %q: row 6 claims content was served, but the "+
					"delivery record carries no origin status: %q", tc.outcome, row.Step)
			}
		})
	}
}

// "Content served" is the strongest claim in the chain, so it is the one a
// drift must never produce by accident. fetch() resolves normally for 404 and
// 500, which is why the status has to be read rather than inferred from the
// outcome — and why everything unrecognizable falls to the weaker branch.
//
// Every case below runs on an outcome the worker DID wait for, so the outcome
// is never what holds the row back: the status alone decides.
func TestBuildLedger_row6ClaimsContentServedOnlyForASuccessStatus(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      string
		wantServed  bool
		wantInEvent string
	}{
		{"a plain 200 is the licensed delivery", "200", true, "answering 200"},
		{"206 is a range response, still content", "206", true, "answering 206"},
		// The whole reason the status exists: fetch() resolves for these, so
		// before it was recorded they were indistinguishable from a success.
		{"404 answered, nothing served", "404", false, "the origin answered 404"},
		{"500 answered, nothing served", "500", false, "the origin answered 500"},
		{"302 is not content", "302", false, "the origin answered 302"},
		// 2xx, and still no body. Calling these "served" would be false in the
		// exact way this row exists to avoid.
		{"204 is success with no body", "204", false, "the origin answered 204"},
		{"205 is success with no body", "205", false, "the origin answered 205"},
		// A worker that stopped recording the status, and one that started
		// recording something else, must both weaken the row rather than
		// promote it.
		{"absent status says so plainly", "", false, "the record carries no origin status"},
		{"a non-numeric status is not trusted", "OK", false, "the origin answered OK"},
		{"an out-of-range number is not trusted", "999", false, "the origin answered 999"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newFixture(t).Sources
			s.Delivery.Outcome = "origin-forwarded"
			s.Delivery.OriginStatus = tc.status

			row := BuildLedger(s).Rows[5]
			served := strings.Contains(row.Step, "content served")
			if served != tc.wantServed {
				t.Errorf("status %q: row 6 step = %q, claims content served = %v, want %v",
					tc.status, row.Step, served, tc.wantServed)
			}
			if !strings.Contains(row.Event, tc.wantInEvent) {
				t.Errorf("status %q: row 6 event = %q, want it to contain %q",
					tc.status, row.Event, tc.wantInEvent)
			}
		})
	}
}

// The sweep knows which point of presence served the request; without it on the
// row an operator has to search CloudWatch by hand to answer "where was this
// served from". A record found without a region still renders, because the
// region is the sweep's knowledge and not something the worker wrote.
func TestBuildLedger_row5NamesThePOPThatServedIt(t *testing.T) {
	s := newFixture(t).Sources
	s.Delivery.Region = "eu-central-1"
	if got := BuildLedger(s).Rows[4].Event; !strings.Contains(got, "served from eu-central-1") {
		t.Errorf("row 5 should name the region the record was found in, got %q", got)
	}

	s = newFixture(t).Sources
	s.Delivery.Region = ""
	got := BuildLedger(s).Rows[4].Event
	if strings.Contains(got, "served from") {
		t.Errorf("row 5 should not claim a region when the sweep recorded none, got %q", got)
	}
	if !strings.Contains(got, "authorized delivery") {
		t.Errorf("row 5 lost its event text when no region was recorded: %q", got)
	}
}

// The obligation is optional: a transaction may mint none. Rendering "PENDING"
// or a zero window for that case would invent a reporting duty that does not
// exist.
func TestBuildLedger_absentObligationIsStatedNotInvented(t *testing.T) {
	s := newFixture(t).Sources
	s.Obligation = nil

	row := BuildLedger(s).Rows[6]
	if !strings.Contains(row.Absence, "no reporting obligation") {
		t.Errorf("row 7 should state the obligation is absent, got %+v", row)
	}
}

func TestObligationEvent_carriesTheOptionalFieldsOnlyWhenPresent(t *testing.T) {
	s := newFixture(t).Sources

	t.Run("pending obligation states neither fulfilment nor quantity", func(t *testing.T) {
		got := BuildLedger(s).Rows[6].Event
		if !strings.HasPrefix(got, "PENDING, due 2026-08-17T12:00:00Z") {
			t.Errorf("event = %q", got)
		}
		if strings.Contains(got, "fulfilled") || strings.Contains(got, "consumed") {
			t.Errorf("a pending obligation reported fulfilment or usage: %q", got)
		}
		// No report was filed against this obligation, so there is no outcome
		// to state. Rendering one would name a refusal that never happened.
		if strings.Contains(got, "REJECTED") || strings.Contains(got, "VALIDATED") {
			t.Errorf("an unreported obligation stated a validation outcome: %q", got)
		}
	})

	t.Run("refused report states the outcome and when it was decided", func(t *testing.T) {
		// An obligation that stays PENDING after a report was filed is the
		// dispute case: the operator has to see why the report was refused,
		// not the same line an unreported obligation renders.
		f := newFixture(t)
		o := f.Sources.Obligation
		outcome := "REJECTED_TOLERANCE"
		o.ValidationOutcome = &outcome
		validated := f.Sources.Evidence.CreatedAt
		o.ValidatedAt = &validated

		got := BuildLedger(f.Sources).Rows[6].Event
		for _, want := range []string{"PENDING", "REJECTED_TOLERANCE", "2026-08-16T12:00:00Z"} {
			if !strings.Contains(got, want) {
				t.Errorf("event %q is missing %q", got, want)
			}
		}
		if strings.Contains(got, "fulfilled") {
			t.Errorf("a refused report reported fulfilment: %q", got)
		}
	})

	t.Run("fulfilled obligation states both", func(t *testing.T) {
		f := newFixture(t)
		o := f.Sources.Obligation
		o.State = "RECEIVED"
		fulfilled := f.Sources.Evidence.CreatedAt
		o.FulfilledAt = &fulfilled
		// The column is NUMERIC(20,8), so the quantity arrives as a decimal
		// string. A fractional value must survive the render untouched:
		// reparsing it as an integer would report a different amount than the
		// row holds, on the one surface whose purpose is stating what happened.
		quantity := "3.50000000"
		o.ConsumedQuantity = &quantity

		got := BuildLedger(f.Sources).Rows[6].Event
		for _, want := range []string{"RECEIVED", "fulfilled 2026-08-16T12:00:00Z", "3.50000000 consumed"} {
			if !strings.Contains(got, want) {
				t.Errorf("event %q is missing %q", got, want)
			}
		}
	})
}

func TestRender_showsEveryRowAndCountsTheAssertions(t *testing.T) {
	var out strings.Builder
	l := BuildLedger(newFixture(t).Sources)

	if err := Render(&out, l); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := out.String()

	for _, want := range []string{
		fixtureTx, fixtureTenant, fixtureOfferID,
		"PARTY", "ASSERTIONS", "7 of 7 checked assertions hold.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered output is missing %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "[x]") {
		t.Errorf("an intact chain rendered a failed assertion:\n%s", got)
	}
}

// The signature and digest columns are abbreviated to fit a terminal, but the
// full value must never be silently replaced by a shortened one anywhere a
// reader might copy it: the assertion details carry the untruncated digests.
func TestRender_assertionDetailsCarryFullDigests(t *testing.T) {
	var out strings.Builder
	f := newFixture(t)
	if err := Render(&out, BuildLedger(f.Sources)); err != nil {
		t.Fatalf("render: %v", err)
	}

	if !strings.Contains(out.String(), f.URLDigest) {
		t.Errorf("the full 64-character URL digest does not appear in the output")
	}
}

func TestRender_failedAssertionsAreVisibleAndCounted(t *testing.T) {
	var out strings.Builder
	s := newFixture(t).Sources
	s.Delivery.URLHash = strings.Repeat("b", 64)

	if err := Render(&out, BuildLedger(s)); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := out.String()

	if !strings.Contains(got, "[x]") {
		t.Errorf("a broken chain rendered no failure mark:\n%s", got)
	}
	if !strings.Contains(got, "6 of 7 checked assertions hold; 1 FAILED.") {
		t.Errorf("the failure was not counted:\n%s", got)
	}
}

// An operator whose Broker tunnel is closed must not see the same output as an
// operator looking at a forged row. The unread checks carry their own mark and
// are counted apart from the ones that ran, and the failure mark stays absent.
func TestRender_unreadSourcesAreNotRenderedAsFailures(t *testing.T) {
	var out strings.Builder
	s := newFixture(t).Sources
	s.Selection = nil
	s.SelectionAbsence = "not read: no Broker database URL configured"

	if err := Render(&out, BuildLedger(s)); err != nil {
		t.Fatalf("render: %v", err)
	}
	got := out.String()

	if strings.Contains(got, "[x]") {
		t.Errorf("an unread source rendered as a failed check:\n%s", got)
	}
	if !strings.Contains(got, "[?]") {
		t.Errorf("an unread source rendered no distinct mark:\n%s", got)
	}
	want := "5 of 5 checked assertions hold; 2 could not be checked because a source was not read."
	if !strings.Contains(got, want) {
		t.Errorf("summary should read %q\n%s", want, got)
	}
}

// A run that is both incomplete AND broken must report the two separately, so
// neither hides the other.
func TestRender_failedAndUnreadAreCountedApart(t *testing.T) {
	var out strings.Builder
	s := newFixture(t).Sources
	s.Selection = nil
	s.SelectionAbsence = "not read: no Broker database URL configured"
	s.Delivery.URLHash = strings.Repeat("c", 64)

	if err := Render(&out, BuildLedger(s)); err != nil {
		t.Fatalf("render: %v", err)
	}
	want := "4 of 5 checked assertions hold; 1 FAILED; 2 could not be checked because a source was not read."
	if !strings.Contains(out.String(), want) {
		t.Errorf("summary should read %q\n%s", want, out.String())
	}
}

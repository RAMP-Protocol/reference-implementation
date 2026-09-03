package exchacct_test

import (
	"context"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
)

// The shape both account calls produce when an Exchange confirms an account.

// TestRegisterAndStatus_AgreeOnAConfirmedAccount pins the shape both account
// calls produce when the Exchange confirms an account.
//
// The two are different RPCs against different response types, and each used to
// build the Account itself from the same five fields. The rule about when Active
// is non-nil was written once, in the field's own doc, and implemented twice —
// so changing how one path derived it left the doc describing both while only
// one followed it. One constructor is what makes the doc a rule rather than a
// description of two independent decisions.
//
// Driven through the service's own two entry points rather than by calling the
// constructor, so what is pinned is that both callers reach it.
func TestRegisterAndStatus_AgreeOnAConfirmedAccount(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	notes := &recordingNotes{}
	svc, err := exchacct.New(exchacct.Config{
		Requirements: publishingNothing{},
		Caller:       &countingCaller{},
		Notes:        notes,
		Clock:        stoppedClock{at: at},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	registered, err := svc.Register(context.Background(), "agent", "exchange.example", nil)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	asked, err := svc.Status(context.Background(), "agent", "exchange.example")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	if !sameConfirmedAccount(registered, asked) {
		t.Errorf("Register produced %+v and Status produced %+v for the same confirmed "+
			"account — the two paths build the value differently", registered, asked)
	}
	// Spelled out rather than left to the equality above, so a change that broke
	// BOTH paths the same way still fails here.
	for name, got := range map[string]exchacct.Account{"register": registered, "status": asked} {
		if !got.Registered {
			t.Errorf("%s: Registered is false for an account the Exchange confirmed", name)
		}
		if got.Active == nil {
			t.Errorf("%s: Active is nil after an authority answered — the field's rule "+
				"is that nil means nobody was asked", name)
		} else if !*got.Active {
			t.Errorf("%s: Active is false, want the peer's answer", name)
		}
		if got.AsOf != at {
			t.Errorf("%s: AsOf = %v, want the instant the call took, %v", name, got.AsOf, at)
		}
		if got.Exchange != "exchange.example" || got.BillingRef != "ref" {
			t.Errorf("%s: got %+v, want the Exchange and handle the peer answered with", name, got)
		}
	}
	// Both paths note the registration, and the note is per Exchange rather than
	// per call, so two confirmations of one account leave one Exchange named
	// twice rather than a second Exchange appearing.
	if len(notes.recorded) != 2 {
		t.Errorf("recorded %v, want both calls to write the note", notes.recorded)
	}
	for _, got := range notes.recorded {
		if got != "exchange.example" {
			t.Errorf("noted %q, want the canonical Exchange", got)
		}
	}
}

// TestConfirmed_StampsTheNoteAndTheAnswerWithOneInstant pins why the timestamp is
// a parameter rather than read where it is used.
//
// A call takes one instant and spends it everywhere: the note it writes and the
// answer it returns describe the same moment. Read the clock a second time inside
// the constructor and the note says one thing while the answer the agent gets
// says another — a note that appears to predate the registration it records.
//
// The clock ticks on every read, which is what makes the second read visible. A
// stopped clock returns the same instant however often it is asked, so it cannot
// tell one read from two.
func TestConfirmed_StampsTheNoteAndTheAnswerWithOneInstant(t *testing.T) {
	t.Parallel()
	clk := &tickingClock{base: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	notes := &recordingNotes{}
	svc, err := exchacct.New(exchacct.Config{
		Requirements: publishingNothing{},
		Caller:       &countingCaller{},
		Notes:        notes,
		Clock:        clk,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := svc.Register(context.Background(), "agent", "exchange.example", nil)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(notes.stamps) != 1 {
		t.Fatalf("wrote %d notes, want 1", len(notes.stamps))
	}
	if !notes.stamps[0].Equal(got.AsOf) {
		t.Errorf("the note says %v and the answer says %v — one call spent two "+
			"instants, so the record and what the agent was told disagree",
			notes.stamps[0], got.AsOf)
	}
	if clk.reads != 1 {
		t.Errorf("the call read the clock %d times, want 1", clk.reads)
	}
}

// TestBothLegsRefuseANonBareDomainBeforeAnythingHappens is the structural half of
// the wire-shape rule, on both account calls.
//
// Register reached this rule through the requirements reader, which runs it
// before it dials. Status ran no shape check at all: it canonicalised whatever it
// was given and handed it to the wire, with only the tool layer's copy in front
// of it. A guarantee one caller holds by convention is not a guarantee, and this
// package's own doc names its consumers as "the MCP adapter today, and whatever
// asks next".
//
// The shared table is what makes this worth driving rather than asserting one
// bad string. Four of its entries separate the rule that IS applied from the
// weaker question of whether a value merely parses as a host — swap in the weak
// rule and those four start passing while every other entry still fails.
//
// Nothing sent and nothing noted is asserted alongside the refusal, because a
// refusal that happened after the request would be the defect wearing the right
// error.

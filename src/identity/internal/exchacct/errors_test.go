package exchacct_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
)

// The error type's own contract: which kind a failure carries, and which kinds
// may reach an operator's log line.

// declaredKinds walks the enum itself so the table below cannot fall behind it.
//
// Kind is a contiguous iota starting at KindUnknown, and String() renders
// anything past the last declared value as "kind(N)". Counting up until that
// happens therefore yields exactly the declared set, without the enum having to
// export a slice of itself for a test's benefit. Append a kind and it appears
// here on the next run.
func declaredKinds() []exchacct.Kind {
	var kinds []exchacct.Kind
	for k := exchacct.Kind(0); !strings.HasPrefix(k.String(), "kind("); k++ {
		kinds = append(kinds, k)
	}
	return kinds
}

// TestSensitive_EveryKindCarriesADecision is the rule the transport asks before
// it writes an operator line, pinned kind by kind.
//
// The transport's guard is one "if": a marked error is answered to the agent and
// never logged, because its text can quote the caller's own registration data.
// Without this table the guard can be deleted, or the predicate made to return
// false, with every other test still passing — the marked kind is not reachable
// through a tool call, so nothing else drives it.
//
// Completeness is mechanical rather than promised. The cases come from the enum
// via declaredKinds, and a kind with no entry in the decision map fails here
// without anyone touching this file. That is the point of the enumeration: the
// default for a new kind is to be logged, and this is where someone has to look
// at that default and agree with it.
func TestSensitive_EveryKindCarriesADecision(t *testing.T) {
	t.Parallel()
	// Each entry is the decision and the reason for it. Only one kind's text can
	// quote the payload: structpb reports a value it cannot pack by quoting it,
	// and that value is the operator's business detail. Every other kind names a
	// condition, never a submitted value.
	decisions := map[exchacct.Kind]struct {
		want bool
		why  string
	}{
		exchacct.KindFieldsMalformed:   {true, "structpb quotes the value it refused"},
		exchacct.KindUnknown:           {false, "reserved, classifies nothing"},
		exchacct.KindExchangeShape:     {false, "names the argument's shape, and the argument is a domain"},
		exchacct.KindNotPermitted:      {false, "names the operator's own policy and the domain it excludes"},
		exchacct.KindRequirements:      {false, "names a manifest that could not be read"},
		exchacct.KindFieldsOutOfBounds: {false, "names the SDK's verdict, not the payload"},
		exchacct.KindFieldsRefused:     {false, "names members at fault, and Fields is a separate channel"},
		exchacct.KindOutbound:          {false, "carries the peer's own text, bounded at the transport"},
		exchacct.KindNotes:             {false, "names this service's own store"},
	}
	for _, kind := range declaredKinds() {
		t.Run(kind.String(), func(t *testing.T) {
			t.Parallel()
			decision, ok := decisions[kind]
			if !ok {
				t.Fatalf("%s has no sensitivity decision — a kind reaches an operator "+
					"line unless someone says it must not, so decide here and say why",
					kind)
			}
			err := &exchacct.Error{Kind: kind, Exchange: "exchange.example", Err: errors.New("cause")}
			if got := exchacct.Sensitive(err); got != decision.want {
				t.Errorf("Sensitive(%s) = %v, want %v — %s",
					kind, got, decision.want, decision.why)
			}
		})
	}
}

// TestDeclaredKinds_CoversTheWholeEnum keeps the walk above honest. If String()
// ever grows a default that does not render "kind(N)", declaredKinds stops at
// the wrong place and the table silently checks fewer kinds than it looks like
// it does — the exact failure the mechanical form exists to remove.
func TestDeclaredKinds_CoversTheWholeEnum(t *testing.T) {
	t.Parallel()
	kinds := declaredKinds()
	if len(kinds) == 0 {
		t.Fatal("declaredKinds found nothing; the walk stopped at KindUnknown")
	}
	last := kinds[len(kinds)-1]
	if last != exchacct.KindNotes {
		t.Errorf("the walk ended at %s, want notes — either a kind was added after "+
			"KindNotes, which is fine and this line moves, or the walk is stopping early",
			last)
	}
	if got := (last + 1).String(); !strings.HasPrefix(got, "kind(") {
		t.Errorf("the value past the enum renders as %q, so the walk cannot tell "+
			"where the enum ends", got)
	}
}

// TestSensitive_IsFalseForAForeignError pins the half of the contract that keeps
// the predicate from becoming a blanket "do not log": it speaks only for errors
// whose text this package built.
func TestSensitive_IsFalseForAForeignError(t *testing.T) {
	t.Parallel()
	for name, err := range map[string]error{
		"a plain error": errors.New("something failed"),
		"nil":           nil,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if exchacct.Sensitive(err) {
				t.Errorf("Sensitive(%v) = true, want false — the predicate speaks only "+
					"for errors this package built", err)
			}
		})
	}
}

// TestRegister_MarksAMalformedPayloadSensitive drives the marked kind through the
// service's own public surface, which is the only surface that reaches it.
//
// It is not reachable through the MCP tool call, and the package documents why:
// every payload arriving there has been through a JSON decode, and neither thing
// structpb refuses survives one. The port takes a Go map and nothing in its
// signature says the caller must be a JSON decoder, so this drives the port.
//
// Both halves are asserted. The kind, because that is what the transport branches
// on; and that the cause quotes the offending value, because the quoting is the
// whole reason the mark exists. If structpb ever stops quoting, the mark is no
// longer needed and this test is where that shows up.
func TestRegister_MarksAMalformedPayloadSensitive(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, &recordingNotes{})

	_, err := svc.Register(context.Background(), "agent", "exchange.example",
		map[string]any{"vat_id": malformedValue})
	if err == nil {
		t.Fatal("Register accepted a payload structpb cannot pack")
	}
	kind, ok := exchacct.KindOf(err)
	if !ok || kind != exchacct.KindFieldsMalformed {
		t.Fatalf("kind = %v (from this package: %v), want %v",
			kind, ok, exchacct.KindFieldsMalformed)
	}
	if !exchacct.Sensitive(err) {
		t.Error("Sensitive = false for a malformed payload — the transport would " +
			"write the quoted value to an operator line")
	}
	// The quoting is the whole reason the mark exists, so it is asserted rather
	// than assumed. The sentinel is a readable run of bytes beside the invalid
	// ones, standing in for the business detail a real payload carries: if it
	// reaches the message, it would reach a log line too.
	cause := exchacct.CauseOf(err)
	if cause == nil {
		t.Fatal("CauseOf = nil, want the pack failure")
	}
	if !strings.Contains(cause.Error(), payloadSentinel) {
		t.Errorf("cause = %q, want it to quote the value it refused — if structpb "+
			"has stopped quoting, the sensitivity mark is no longer needed", cause)
	}
}

// TestRegister_SendsNothingWhenThePayloadIsMalformed pins the other half of the
// same refusal: it happens before the wire, so a payload this service cannot
// pack never reaches the Exchange.
func TestRegister_SendsNothingWhenThePayloadIsMalformed(t *testing.T) {
	t.Parallel()
	notes := &recordingNotes{}
	peer := &countingCaller{}
	svc, err := exchacct.New(exchacct.Config{
		Requirements: publishingNothing{},
		Caller:       peer,
		Notes:        notes,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := svc.Register(context.Background(), "agent", "exchange.example",
		map[string]any{"vat_id": malformedValue}); err == nil {
		t.Fatal("Register accepted a payload structpb cannot pack")
	}
	if peer.registers != 0 {
		t.Errorf("sent %d register calls, want 0 — the pack failure is before the wire",
			peer.registers)
	}
	if len(notes.recorded) != 0 {
		t.Errorf("wrote %d notes, want 0 — nothing was registered", len(notes.recorded))
	}
}

// TestKindUnknown_IsTheZeroValueAndNamesNoClassification pins the reservation.
//
// An Error built without a Kind must not read as a real classification. Start the
// enum at KindRequirements again and this fails: the value renders as
// "requirements" and dispatches through that arm, claiming a decision nobody
// made. The three sibling error enums on this surface reserve their zero the same
// way, so this is also what keeps them consistent.
func TestKindUnknown_IsTheZeroValueAndNamesNoClassification(t *testing.T) {
	t.Parallel()
	var zero exchacct.Kind
	if zero != exchacct.KindUnknown {
		t.Errorf("the zero Kind is %v, want KindUnknown — a value built without a "+
			"Kind is claiming a classification nobody made", zero)
	}
	if got := zero.String(); got != "unknown" {
		t.Errorf("zero Kind renders as %q, want \"unknown\"", got)
	}
	// And it reaches the rendered error, which is where an operator meets it.
	err := &exchacct.Error{Exchange: "exchange.example"}
	if got := err.Error(); got != "exchacct: unknown at exchange.example" {
		t.Errorf("Error() = %q, want the unclassified rendering", got)
	}
}

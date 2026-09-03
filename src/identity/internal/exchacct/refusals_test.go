package exchacct_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
)

// What this service refuses about the exchange ARGUMENT, before it reads,
// rewrites or sends anything.

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
func TestBothLegsRefuseANonBareDomainBeforeAnythingHappens(t *testing.T) {
	t.Parallel()
	for _, tc := range testutil.NonBareDomains {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			bad := tc.Of("exchange.example")
			legs := map[string]func(*exchacct.Service) error{
				"register": func(s *exchacct.Service) error {
					_, err := s.Register(context.Background(), "agent", bad, nil)
					return err
				},
				"status": func(s *exchacct.Service) error {
					_, err := s.Status(context.Background(), "agent", bad)
					return err
				},
			}
			for name, call := range legs {
				notes, peer := &recordingNotes{}, &countingCaller{}
				svc, err := exchacct.New(exchacct.Config{
					Requirements: publishingNothing{}, Caller: peer, Notes: notes,
				})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				err = call(svc)
				if err == nil {
					t.Fatalf("%s accepted %q", name, bad)
				}
				if kind, ok := exchacct.KindOf(err); !ok || kind != exchacct.KindExchangeShape {
					t.Errorf("%s: kind = %v, want %v — a refused argument must not read "+
						"as the Exchange failing to answer", name, kind, exchacct.KindExchangeShape)
				}
				if peer.registers != 0 || peer.statuses != 0 {
					t.Errorf("%s: reached the wire with %q", name, bad)
				}
				if len(notes.recorded) != 0 {
					t.Errorf("%s: wrote a note for %q", name, bad)
				}
			}
		})
	}
}

// TestCheckExchange_RefusesTheValueAsWritten pins the ordering: the rule runs
// before canonicalisation, so the caller is refused the value it sent rather
// than one this service rewrote.
//
// Canonicalising lowercases, trims and folds a written-out :443. Check after
// that rewrite and the error quotes a value the caller never wrote, which is the
// "silently reinterpreted" outcome the tool layer's own rule argues against —
// these calls open accounts and move money.
func TestCheckExchange_RefusesTheValueAsWritten(t *testing.T) {
	t.Parallel()
	const bad = "  HTTPS://Exchange.Example:443/register  "
	svc := newTestService(t, &recordingNotes{})

	_, err := svc.Register(context.Background(), "agent", bad, nil)
	if err == nil {
		t.Fatal("Register accepted a URL")
	}
	if got := exchacct.ExchangeOf(err); got != bad {
		t.Errorf("the refusal names %q, want the value as written, %q — a caller told "+
			"its input was wrong must be shown the input it sent", got, bad)
	}
}

// TestRequirements_ClassifiesWhatTheReaderRefused gives the port's two sentinels
// a reader.
//
// The requirements reader distinguishes a refused argument and a policy refusal
// from a peer that would not answer, and says so with sentinels. Every one of
// them used to arrive as KindRequirements — "the manifest could not be read" —
// so an operator reading call_failed could not tell a domain their own policy
// excludes from an Exchange that is down, and the two have different remedies.
func TestRequirements_ClassifiesWhatTheReaderRefused(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		refusal error
		want    exchacct.Kind
	}{
		"a policy refusal":    {account.ErrNotPermitted, exchacct.KindNotPermitted},
		"a refused argument":  {account.ErrNotBareDomain, exchacct.KindExchangeShape},
		"a peer that is down": {errors.New("connection refused"), exchacct.KindRequirements},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			svc, err := exchacct.New(exchacct.Config{
				Requirements: refusingReader{err: tc.refusal},
				Caller:       &countingCaller{},
				Notes:        &recordingNotes{},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = svc.Register(context.Background(), "agent", "exchange.example", nil)
			if err == nil {
				t.Fatal("Register went ahead with requirements that were refused")
			}
			if kind, ok := exchacct.KindOf(err); !ok || kind != tc.want {
				t.Errorf("kind = %v, want %v", kind, tc.want)
			}
		})
	}
}

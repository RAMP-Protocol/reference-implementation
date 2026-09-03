package exchacct_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
)

// The doubles and values every test in this package shares, so a second test
// does not grow a near-copy of one under a different name.

// payloadSentinel stands in for the business detail a real registration carries.
// It is readable so a failure message shows plainly what leaked.
const payloadSentinel = "VAT-SENTINEL-0000"

// malformedValue is the one thing that reaches structpb.NewStruct as a refusal.
//
// It is raw invalid UTF-8, NOT NaN or infinity. Those two never get this far:
// helpers.CheckRegistrationData canonicalises the payload first and answers
// "uncanonicalizable" for both, which this service reports as
// KindFieldsOutOfBounds. Invalid UTF-8 passes that check and fails at the pack,
// where structpb quotes what it was given.
//
// Nor can it arrive through the MCP surface, which is the point of driving the
// port directly: a JSON decoder turns an unpaired surrogate escape into U+FFFD,
// which is valid UTF-8. These bytes come from a caller that builds the map
// itself, which is exactly the second caller the kind's doc says can reach it.
var malformedValue = payloadSentinel + string([]byte{0xff, 0xfe})

func newTestService(t *testing.T, notes account.RegistrationLog) *exchacct.Service {
	t.Helper()
	svc, err := exchacct.New(exchacct.Config{
		Requirements: publishingNothing{},
		Caller:       &countingCaller{},
		Notes:        notes,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

// stoppedClock makes AsOf comparable across two calls, which is the point of the
// test that uses it: with a wall clock the two answers differ by however long the
// second call took, and the field could not be compared at all.
type stoppedClock struct{ at time.Time }

func (c stoppedClock) Now() time.Time { return c.at }

// After is never called on this path. It returns a channel that never fires
// rather than nil, so a future caller blocks visibly instead of panicking.
func (stoppedClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }

// tickingClock moves one second every time it is read, which turns "how many
// times did this call read the clock?" into something a test can assert on. A
// stopped clock cannot: every read returns the same instant, so an extra one is
// invisible.
type tickingClock struct {
	base  time.Time
	reads int
}

func (c *tickingClock) Now() time.Time {
	c.reads++
	return c.base.Add(time.Duration(c.reads) * time.Second)
}

func (*tickingClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }

// publishingNothing is an Exchange that publishes no schema and no terms digest,
// which is the normal absent case and leaves the pack step as the only thing
// between the caller's map and the wire.
type publishingNothing struct{}

func (publishingNothing) Requirements(context.Context, string) (account.Requirements, error) {
	return account.Requirements{}, nil
}

// countingCaller records how many times the wire was reached. It answers rather
// than fails, so a test asserting "nothing was sent" cannot pass because the send
// happened and errored.
type countingCaller struct {
	registers int
	statuses  int
}

func (c *countingCaller) Register(
	context.Context, *rampv1.RegisterRequest,
) (*rampv1.RegisterResponse, error) {
	c.registers++
	return &rampv1.RegisterResponse{
		Ver: helpers.ProtocolVersion, Active: true, BillingRef: "ref",
	}, nil
}

func (c *countingCaller) AccountStatus(
	context.Context, *rampv1.GetAccountStatusRequest,
) (*rampv1.GetAccountStatusResponse, error) {
	c.statuses++
	return &rampv1.GetAccountStatusResponse{
		Ver: helpers.ProtocolVersion, Active: true, BillingRef: "ref",
	}, nil
}

type recordingNotes struct {
	recorded []string
	// stamps holds the instant each note was written with, so a test can compare
	// it against the answer the same call returned.
	stamps []time.Time
}

func (n *recordingNotes) Record(_ context.Context, _, exchange string, at time.Time) error {
	n.recorded = append(n.recorded, exchange)
	n.stamps = append(n.stamps, at)
	return nil
}

func (n *recordingNotes) Forget(context.Context, string, string) error { return nil }

func (n *recordingNotes) List(context.Context, string) ([]account.ExchangeRegistration, error) {
	return nil, nil
}

// sameConfirmedAccount compares two Accounts the way this value's contract means
// them to be compared.
//
// Not ==, because Active is a *bool and struct equality compares the two
// pointers. Two calls always produce different pointers, so == could never hold
// and a test written that way would fail whatever the code did.
func sameConfirmedAccount(a, b exchacct.Account) bool {
	if (a.Active == nil) != (b.Active == nil) {
		return false
	}
	return a.Exchange == b.Exchange &&
		a.Registered == b.Registered &&
		a.IsActive() == b.IsActive() &&
		a.BillingRef == b.BillingRef &&
		a.AsOf.Equal(b.AsOf)
}

// refusingReader is a requirements reader that refuses with a chosen cause,
// wrapped the way the real one wraps its sentinels.
type refusingReader struct{ err error }

func (r refusingReader) Requirements(context.Context, string) (account.Requirements, error) {
	return account.Requirements{}, fmt.Errorf("%w: exchange.example", r.err)
}

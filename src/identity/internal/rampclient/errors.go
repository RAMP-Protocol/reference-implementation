package rampclient

import (
	"errors"
	"fmt"
	"net/http"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampreason"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
)

// Kind classifies why an outbound RAMP call failed, so a caller can branch on
// the class without reading the message.
type Kind int

const (
	// KindUnknown is the zero value; it carries no classification.
	KindUnknown Kind = iota
	// KindRefused is a peer that answered and said no. Detail carries the typed
	// reason when the peer supplied one.
	KindRefused
	// KindUnreachable is a peer that did not answer: dial failure, timeout,
	// refused redirect, blocked target.
	KindUnreachable
	// KindMalformed is an answer that arrived but could not be understood.
	KindMalformed
)

// There is deliberately no kind for "refused here, before anything was sent".
// The SDK already has one — rampsdkconnect.CallNotSent — and the routing
// refusals are reported with it, so the same condition carries the same token
// whichever leg produced it. A local kind would be a second vocabulary kept in
// step with the first by spelling alone.

// kindStrings names each Kind for logging. Parity with exchange.Kind and
// broker.Kind, which both render their kind rather than logging a bare integer.
var kindStrings = map[Kind]string{
	KindRefused:     "refused",
	KindUnreachable: "unreachable",
	KindMalformed:   "malformed",
}

// String renders Kind for logging.
func (k Kind) String() string {
	if s, ok := kindStrings[k]; ok {
		return s
	}
	return "unknown"
}

// Error is this package's canonical error. It exists so the typed RAMP reason
// survives the trip to the transport layer instead of being rendered into a
// string here: the layer that talks to the agent decides how a refusal reads,
// and it can only do that if the reason is still a value when it arrives.
//
// Detail is the peer's own ErrorDetail when it sent one. Status is the HTTP
// status for the relay leg (0 for the Connect legs, whose code travels on the
// wrapped *connect.Error).
type Error struct {
	Kind   Kind
	Op     string
	Status int
	Detail *rampv1.ErrorDetail
	Err    error
}

func (e *Error) Error() string {
	switch {
	case e.Reason() != "":
		return fmt.Sprintf("rampclient: %s refused (%s): %s",
			e.Op, e.Reason(), e.Detail.GetMessage())
	case e.Detail.GetMessage() != "":
		return fmt.Sprintf("rampclient: %s refused (%s): %s",
			e.Op, e.statusText(), e.Detail.GetMessage())
	case e.Status != 0:
		return fmt.Sprintf("rampclient: %s refused (%s)", e.Op, e.statusText())
	case e.Err != nil:
		return fmt.Sprintf("rampclient: %s: %v", e.Op, e.Err)
	default:
		return "rampclient: " + e.Op + " failed"
	}
}

// statusText renders the HTTP status as both code and phrase. The code is what a
// reader greps for and the phrase is what they understand; emitting one without
// the other is how "(HTTP Not Found)" ends up next to "(HTTP 404)" in sibling
// branches of the same function.
func (e *Error) statusText() string {
	if txt := http.StatusText(e.Status); txt != "" {
		return fmt.Sprintf("HTTP %d %s", e.Status, txt)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

func (e *Error) Unwrap() error { return e.Err }

// Reason is the typed reason token the peer supplied, or "" when it sent none.
// Rendered by internal/rampreason, which every outbound leg reads, so no two of
// them can name the same refusal differently.
func (e *Error) Reason() string {
	if e.Detail == nil {
		return ""
	}
	return rampreason.Name(e.Detail)
}

// noAccount labels an account-status failure that is really the "not registered"
// answer, by wrapping account.ErrNoAccount. The cause is kept underneath, so the
// layer that renders a refusal can still recover the code and any typed detail.
//
// The CLASSIFICATION is here because this package owns the Connect vocabulary.
// GetAccountStatus carries no typed denial in the protocol today, so the answer
// arrives as a bare NotFound and something has to read it; a caller that read
// the code itself would be deciding a domain answer, and a mutation, from a wire
// detail it has no other reason to know. If the protocol later gives this answer
// a reason of its own, this is the one function that changes.
//
// The SENTINEL is not here, and that split is deliberate. It is part of what the
// account leg promises whoever consumes it, so it belongs beside that port in
// account rather than inside one client that happens to satisfy it today — this
// package goes when the two account RPCs land in the SDK, and a consumer holding
// errors.Is against a sentinel defined here would go quiet at exactly that
// moment, turning a normal "not registered" answer into a tool failure.
func noAccount(exchange string, err error) error {
	var connErr *connect.Error
	if errors.As(err, &connErr) && connErr.Code() == connect.CodeNotFound {
		return fmt.Errorf("%w %s: %w", account.ErrNoAccount, exchange, err)
	}
	return err
}

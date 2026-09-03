package exchacct

import (
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Kind classifies why an account operation did not produce an account. The tool
// layer branches on it to decide what the agent is told and what the operator
// sees, which is the whole reason it exists: each kind has a different remedy,
// and one opaque error would make them read alike.
type Kind int

const (
	// KindUnknown is the zero value, reserved so it classifies nothing. An Error
	// built without a Kind would otherwise render as the first real classification
	// and dispatch through its arm, claiming a decision nobody made. The three
	// sibling enums on this surface reserve their zero value the same way.
	KindUnknown Kind = iota
	// KindExchangeShape means the exchange ARGUMENT is not the shape a
	// domain-valued field admits. Refused before the value is canonicalised,
	// read or sent, so nothing was rewritten and nothing was dialled.
	//
	// It is separate from KindRequirements because the remedy is: the caller
	// wrote a bad value, where a requirements failure means the Exchange did not
	// answer. Both used to render as the second.
	KindExchangeShape
	// KindNotPermitted means this deployment's Exchange policy excludes the
	// target. Nothing was dialled. The remedy is the operator's setting, not the
	// agent's argument and not the peer, which is why it is its own kind.
	KindNotPermitted
	// KindRequirements means the target Exchange's manifest could not be read,
	// so there was nothing to pre-check against and no terms digest to echo.
	// Nothing was signed and nothing was sent.
	KindRequirements
	// KindFieldsOutOfBounds means the payload exceeds what the protocol lets a
	// registration carry — its size, its member count, or how deeply it nests.
	// Checked before anything is fetched or signed, because a limit that exists
	// to stop work belongs before the work it would stop. Err names the SDK's
	// verdict.
	KindFieldsOutOfBounds
	// KindFieldsMalformed means the payload holds a value that cannot travel on
	// the wire at all, independently of any schema. Err is the packing failure,
	// and it QUOTES the offending value — see Sensitive.
	//
	// One thing reaches it: a string holding invalid UTF-8. NaN and infinity are
	// the other two values structpb refuses, but neither arrives, because
	// helpers.CheckRegistrationData canonicalises the payload first and answers
	// "uncanonicalizable" for both — so they are reported as
	// KindFieldsOutOfBounds and never reach the pack.
	//
	// NOT REACHABLE through the MCP surface, which is why the test for it drives
	// the port rather than a tool call. Every payload arriving at a tool has been
	// through a JSON decode, and an unpaired surrogate escape decodes to U+FFFD,
	// which is valid UTF-8. The arm stays because the port takes a Go map and
	// nothing in its signature says the caller must be a JSON decoder — a second
	// caller that builds the map itself can reach it, and the package's own test
	// is that caller.
	KindFieldsMalformed
	// KindFieldsRefused means the local pre-check found that the payload does
	// not match the schema that Exchange publishes. Nothing was signed and
	// nothing was sent; Fields names each member at fault.
	KindFieldsRefused
	// KindOutbound means the request was sent and the Exchange refused it, or
	// the call never completed. The cause travels underneath, so the layer that
	// renders it can still recover the protocol's typed reason.
	KindOutbound
	// KindNotes means this service's own note store failed on a path whose
	// answer depends on it. It is NOT used where a note is bookkeeping beside an
	// answer already in hand — those failures are logged and the call succeeds.
	//
	// It is the one kind that names no Exchange: the failed read is about the
	// agent's whole note set, so Error.Exchange is empty.
	KindNotes
)

func (k Kind) String() string {
	switch k {
	case KindUnknown:
		return "unknown"
	case KindExchangeShape:
		return "exchange_shape"
	case KindNotPermitted:
		return "not_permitted"
	case KindRequirements:
		return "requirements"
	case KindFieldsOutOfBounds:
		return "fields_out_of_bounds"
	case KindFieldsMalformed:
		return "fields_malformed"
	case KindFieldsRefused:
		return "fields_refused"
	case KindOutbound:
		return "outbound"
	case KindNotes:
		return "notes"
	default:
		return fmt.Sprintf("kind(%d)", int(k))
	}
}

// Error is this package's one error type, per the repository's rule that a
// service package carries a single domain error with a kind enum rather than
// letting naked errors escape to transport.
//
// Err is kept and unwrapped rather than rendered into the message, which matters
// most for KindOutbound: the protocol's typed reason lives on the cause, and a
// reason flattened into prose here could not be recovered by the layer whose job
// is rendering it.
type Error struct {
	Kind Kind
	// Exchange is the domain the operation was about.
	//
	// Empty on KindNotes, and only there: that failure is about this agent's
	// whole note set rather than about one Exchange, so there is no domain to
	// name. Error() and ExchangeOf both say what they do with an empty value.
	Exchange string
	// Fields names the members a KindFieldsRefused pre-check rejected. Empty on
	// every other kind. It is the protocol's own type because the same shape
	// comes back from the Exchange's own refusal, and one renderer serves both.
	Fields []*rampv1.RegistrationFieldError
	Err    error
}

// Error renders the failure. The "at <domain>" clause is dropped when there is no
// domain, rather than rendered as a dangling "at ": a KindNotes failure is about
// the agent's whole note set, and a clause promising a domain it does not have
// would have a reader look for one.
func (e *Error) Error() string {
	at := ""
	if e.Exchange != "" {
		at = " at " + e.Exchange
	}
	if e.Err == nil {
		return fmt.Sprintf("exchacct: %s%s", e.Kind, at)
	}
	return fmt.Sprintf("exchacct: %s%s: %v", e.Kind, at, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// sensitive reports whether this error's text may contain the caller's own
// registration data, and so must reach the caller but never a log line.
//
// Exactly one kind can today. structpb reports a value it cannot pack by
// quoting it — "invalid UTF-8 in string: %q" is the one this service can reach —
// and registration data is the operator's business detail, which this service passes
// through without logging or storing. The privacy guard over the log call sites
// matches on the identifiers this data travels under, so it would not catch a
// line built from a message that merely embeds the value.
//
// Sensitive is the exported reader. It is what the transport asks before it
// writes an operator line, so this predicate is the rule rather than a
// description of one written somewhere else.
func (e *Error) sensitive() bool {
	return e.Kind == KindFieldsMalformed
}

// errorOf returns err as this package's error, so a caller branching on the kind
// does not declare the variable at every call site.
func errorOf(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// KindOf returns err's kind, and whether err came from this package at all.
func KindOf(err error) (Kind, bool) {
	e, ok := errorOf(err)
	if !ok {
		return 0, false
	}
	return e.Kind, true
}

// ExchangeOf returns the domain the failed operation was about.
//
// Empty in two cases a caller must not confuse: err did not come from this
// package at all, or it is a KindNotes failure, which is about the agent's whole
// note set and names no Exchange. KindOf separates them.
func ExchangeOf(err error) string {
	e, ok := errorOf(err)
	if !ok {
		return ""
	}
	return e.Exchange
}

// Sensitive reports whether err's text may quote the caller's own registration
// data, so the layer rendering it must answer the caller and write no log line.
//
// False for an error that did not come from this package: this predicate speaks
// only for errors whose text this package built.
func Sensitive(err error) bool {
	e, ok := errorOf(err)
	return ok && e.sensitive()
}

// CauseOf returns the failure underneath, or nil when err did not come from this
// package or carries no cause.
//
// It exists so a consumer rendering a message reaches the cause the same way the
// other accessors reach their fields — through errors.As, which tolerates
// wrapping. errors.Unwrap at a call site returns the OUTER error the moment
// anything wraps this one, and the agent's message then starts with this
// package's own prefix instead of the cause it was meant to quote.
func CauseOf(err error) error {
	e, ok := errorOf(err)
	if !ok {
		return nil
	}
	return e.Err
}

// FieldsOf returns the members a pre-check refused, or nil when err is not a
// KindFieldsRefused error.
func FieldsOf(err error) []*rampv1.RegistrationFieldError {
	e, ok := errorOf(err)
	if !ok || e.Kind != KindFieldsRefused {
		return nil
	}
	return e.Fields
}

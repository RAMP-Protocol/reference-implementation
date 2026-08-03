package delivery

import (
	"fmt"
	"net/http"
)

// Kind classifies why a content fetch failed, so a caller can branch on the
// class without reading the message. The MCP layer reports a failed fetch to the
// agent rather than failing the tool call, so the class is what shapes what the
// agent is told and whether retrying its own fetch is worth suggesting.
type Kind int

const (
	// KindUnknown is the zero value; it carries no classification.
	KindUnknown Kind = iota
	// KindRefused is an edge that answered and said no — a 4xx or 5xx. Reason
	// carries the edge's own token when it sent one.
	KindRefused
	// KindUnreachable is an edge that did not answer: dial failure, timeout,
	// refused redirect, blocked target.
	KindUnreachable
	// KindTooLarge is a body past the configured cap. Deliberately distinct from
	// KindRefused: the edge did nothing wrong and the URL is still good, so the
	// agent can fetch it itself with whatever budget it has.
	KindTooLarge
	// KindNotSignable is custody declining or failing to produce the key this
	// fetch must be signed with. No request leaves on this path.
	//
	// A custody backend that hangs lands here too, as a context deadline: the
	// fetch timeout covers key resolution, and nothing had left the process when
	// it expired. That is the promise this kind makes, and it is why a stalled
	// Vault does not report as an unreachable edge.
	KindNotSignable
	// KindMalformed is a delivery URL this client cannot sign faithfully.
	KindMalformed
)

// kindStrings names each Kind for logging and for the reason an agent sees when
// the edge supplied none. Parity with rampclient.Kind, which renders its kind
// rather than logging a bare integer.
var kindStrings = map[Kind]string{
	KindRefused:     "refused",
	KindUnreachable: "unreachable",
	KindTooLarge:    "too_large",
	KindNotSignable: "not_signable",
	KindMalformed:   "malformed",
}

// String renders Kind for logging.
func (k Kind) String() string {
	if s, ok := kindStrings[k]; ok {
		return s
	}
	return "unknown"
}

// Error is this package's canonical error.
//
// Reason exists so the edge's own refusal token — missing_agent_key,
// keyid_mismatch, thumbprint_mismatch, pop_expired — survives as a value rather
// than being flattened into a sentence here. Those tokens are the difference
// between "the publisher refused us" and "our custody wiring is broken", and the
// layer that decides how a refusal reads to an agent can only tell them apart if
// the token is still intact when it arrives.
type Error struct {
	Kind   Kind
	Op     string
	Status int    // HTTP status when the edge answered; 0 otherwise
	Reason string // the edge's refusal token when it sent one
	Err    error
}

func (e *Error) Error() string {
	msg := "delivery: " + e.Op + ": " + e.Kind.String()
	if e.Status != 0 {
		// StatusText is empty for a code net/http does not know, and a bare
		// "(599 )" reads like a truncation. The number alone is the honest render.
		if text := http.StatusText(e.Status); text != "" {
			msg += fmt.Sprintf(" (HTTP %d %s)", e.Status, text)
		} else {
			msg += fmt.Sprintf(" (HTTP %d)", e.Status)
		}
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap keeps the cause matchable, so a caller can still reach a custody
// sentinel (keystore.ErrUnavailable, agentsign.ErrNotSignable) through
// errors.Is after the failure has been classified here.
func (e *Error) Unwrap() error { return e.Err }

// ReasonOf returns the most specific machine-readable reason available: the
// edge's own token when it sent one, otherwise the failure class.
func (e *Error) ReasonOf() string {
	if e.Reason != "" {
		return e.Reason
	}
	return e.Kind.String()
}

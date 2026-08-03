package rampclient

import (
	"fmt"
	"net/http"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
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
func (e *Error) Reason() string {
	if e.Detail == nil {
		return ""
	}
	return ReasonName(e.Detail)
}

// ReasonName renders the populated arm of a RAMP ErrorDetail's reason oneof as a
// short, stable token an agent can branch on — DENIAL_REASON_OFFER_EXPIRED rather
// than a code an agent has no schema for. It is the single reader of the reason
// oneof, shared by the relay error path here and the Connect error path in the
// MCP tools, so the two cannot disagree on how a refusal is named.
//
// Each arm is a distinct failure KIND — a denial is an access decision, a
// rejection a refused submission, a failure an operation that could not complete
// — and the enum inside names the specific cause. An empty result means the
// detail carried no reason, and the caller falls back to the transport status.
func ReasonName(detail *rampv1.ErrorDetail) string {
	switch r := detail.GetReason().(type) {
	case *rampv1.ErrorDetail_TransactionDenial:
		return EnumName(r.TransactionDenial.GetReason())
	case *rampv1.ErrorDetail_RegistrationFailure:
		return EnumName(r.RegistrationFailure.GetReason())
	case *rampv1.ErrorDetail_UsageReportRejection:
		return EnumName(r.UsageReportRejection.GetReason())
	case *rampv1.ErrorDetail_CatalogRejection:
		return EnumName(r.CatalogRejection.GetReason())
	case *rampv1.ErrorDetail_RetrievalAuthFailure:
		return EnumName(r.RetrievalAuthFailure.GetReason())
	default:
		// The remaining arms (dispute, domain verification) belong to RPCs this
		// adapter does not call; the transport status carries them adequately.
		return ""
	}
}

// EnumName renders a protobuf enum value by its declared name. The zero value
// means "unset" in every RAMP reason enum and reports nothing rather than a name.
func EnumName(v protoreflect.Enum) string {
	if v.Number() == 0 {
		return ""
	}
	if d := v.Descriptor().Values().ByNumber(v.Number()); d != nil {
		return string(d.Name())
	}
	return ""
}

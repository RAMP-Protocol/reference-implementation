// Package rampreason renders the typed reason a RAMP peer sends into the short,
// stable token a caller branches on.
//
// It sits in shared internal code because the answer belongs to the protocol
// rather than to any one client. Two of this service's outbound legs need it —
// the SDK's Connect errors and the relay's own — and a third caller is the MCP
// adapter, which reads the reason enums a discovery result carries. None of them
// is the natural owner, and while it lived inside the registration client every
// new use added a dependency on a package scheduled for deletion.
package rampreason

import (
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Name renders the populated arm of a RAMP ErrorDetail's reason oneof as a short,
// stable token an agent can branch on — DENIAL_REASON_OFFER_EXPIRED rather than a
// code an agent has no schema for. It is the single reader of the reason oneof,
// so no two callers can disagree on how a refusal is named.
//
// Each arm is a distinct failure KIND — a denial is an access decision, a
// rejection a refused submission, a failure an operation that could not complete
// — and the enum inside names the specific cause. An empty result means the
// detail carried no reason, and the caller falls back to the transport status.
//
// Which arm is populated is the SDK's question, answered once there for all SEVEN
// of them. An earlier version of this restated five and dropped the other two on
// the grounds that no caller reached those RPCs — true when written, and the kind
// of premise that stops being true without anyone noticing, because the arm it
// silences renders as "no reason given" rather than as a gap. Reading the SDK's
// accessor and naming whatever it returns removes the premise: an arm added
// upstream arrives named, without an edit here.
func Name(detail *rampv1.ErrorDetail) string {
	switch reason := helpers.Reason(detail).(type) {
	case protoreflect.Enum:
		return EnumName(reason)
	default:
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

// EnumPtrName renders an OPTIONAL reason enum. The pointer is the protocol's way
// of separating "the responder stated no reason" from the unspecified value, and
// both render empty here — but only one of them is an omission, so the
// distinction is preserved upstream rather than collapsed at the wire.
func EnumPtrName[E protoreflect.Enum](v *E) string {
	if v == nil {
		return ""
	}
	return EnumName(*v)
}

// Package exchange holds cross-cutting domain types for the Exchange service.
// The canonical error type lives here so service and transport layers share
// the same vocabulary without importing each other.
package exchange

import (
	"errors"
	"fmt"

	connect "connectrpc.com/connect"
)

// Kind enumerates the failure modes the Exchange classifies. Each Kind maps
// to a connect.Code at the transport boundary (see ConnectCode).
type Kind int

// Kind values. Each maps to a connect.Code at the handler boundary.
const (
	KindUnspecified Kind = iota
	KindInvalidRequest
	KindNotFound
	KindSignatureInvalid
	KindBillingDenied
	KindIdempotent // already-processed idempotency replay
	KindInternal
	// KindUnauthenticated is for delegation verification failures that are
	// caller-attributable (bad/expired Biscuit, unknown principal domain).
	KindUnauthenticated
	// KindFailedPrecondition signals state-level invariants (e.g. a
	// post-verification identity-mismatch check on ReportUsage).
	KindFailedPrecondition
	// KindPermissionDenied signals that a biscuit chain-verified but the
	// Exchange policy layer refused it — for example because the
	// authority or attenuation kid is on the issuer's revocation list
	// (ye6f-19, ADR-003 §5). Maps to connect.CodePermissionDenied.
	KindPermissionDenied
	// KindUnimplemented signals an operation the adapter or handler does not
	// implement — e.g. a billing adapter with no reverse-transfer primitive
	// returning ErrRefundUnsupported. Maps to connect.CodeUnimplemented.
	KindUnimplemented
	// Refusal-reason taxonomy (cluster w54d, obligation 05). Each kind
	// names a distinct biscuit-failure mode at the wire boundary so
	// operator tooling can triage. All map to CodeUnauthenticated at
	// the Connect layer — the discriminator is the Kind tag plus the
	// canonical message prefix carried in Error.Message.
	//
	// KindEntitlementMissing — caller presented no entitlement biscuit
	// for a subscription-only offer.
	KindEntitlementMissing
	// KindEntitlementMalformed — biscuit bytes failed the Biscuit v2
	// protobuf decode (ErrMalformed at the verifier layer).
	KindEntitlementMalformed
	// KindEntitlementExpired — biscuit's authority validity window has
	// passed (ErrExpired at the verifier layer).
	KindEntitlementExpired
	// KindEntitlementWrongBuyer — biscuit's subscriber_org fact does
	// not match the caller's asserted buyer organization. Crypto +
	// TTL pass; only the buyer binding is wrong.
	KindEntitlementWrongBuyer
	// KindSubscriptionLapsed — the subscription itself has lapsed on
	// the resource owner's side (distinct from the biscuit's TTL — the
	// covering contract is no longer valid). Today this surfaces via
	// the same ErrExpired path; reserved for the future grant-map
	// branch where the subscription contract is queried independently.
	KindSubscriptionLapsed
	// KindEntitlementNotGranted — the subscription exists for some
	// buyer org but no buyer-side grant ties this caller to it. The
	// biscuit is sound but does not name this caller's org.
	KindEntitlementNotGranted
	// KindEntitlementStaleAttenuation — the biscuit chain-verified but
	// the per-request attenuation block is missing or stale beyond the
	// platform's tolerance (ADR-002 §B mandate; ADR-007 wiring). The
	// biscuit's authority is sound; only the freshness contract is
	// broken. Distinct family so operator tooling can triage the
	// "stolen authority replayed without fresh attenuation" mode
	// separately from the missing/malformed/expired/wrong-buyer modes.
	KindEntitlementStaleAttenuation
)

// Error is the canonical domain error. Handlers receive it from the service
// layer and convert it to a connect.Error at the boundary.
type Error struct {
	Kind    Kind
	Message string
	Err     error
}

// Error implements error.
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Kind, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e *Error) Unwrap() error { return e.Err }

// kindStrings maps each Kind to its lowercase log token. Map dispatch
// keeps Kind.String under the gocyclo cap as new families are added.
var kindStrings = map[Kind]string{
	KindInvalidRequest:              "invalid_request",
	KindNotFound:                    "not_found",
	KindSignatureInvalid:            "signature_invalid",
	KindBillingDenied:               "billing_denied",
	KindIdempotent:                  "idempotent",
	KindInternal:                    "internal",
	KindUnauthenticated:             "unauthenticated",
	KindFailedPrecondition:          "failed_precondition",
	KindPermissionDenied:            "permission_denied",
	KindUnimplemented:               "unimplemented",
	KindEntitlementMissing:          "entitlement_missing",
	KindEntitlementMalformed:        "entitlement_malformed",
	KindEntitlementExpired:          "entitlement_expired",
	KindEntitlementWrongBuyer:       "entitlement_wrong_buyer",
	KindSubscriptionLapsed:          "subscription_lapsed",
	KindEntitlementNotGranted:       "entitlement_not_granted",
	KindEntitlementStaleAttenuation: "entitlement_stale_attenuation",
}

// String renders Kind for logging.
func (k Kind) String() string {
	if s, ok := kindStrings[k]; ok {
		return s
	}
	return "unspecified"
}

// ConnectCode maps a Kind to the connect.Code the transport layer returns.
func (k Kind) ConnectCode() connect.Code {
	switch k {
	case KindInvalidRequest:
		return connect.CodeInvalidArgument
	case KindNotFound:
		return connect.CodeNotFound
	case KindSignatureInvalid:
		return connect.CodeUnauthenticated
	case KindBillingDenied:
		return connect.CodePermissionDenied
	case KindIdempotent:
		return connect.CodeAlreadyExists
	case KindInternal:
		return connect.CodeInternal
	case KindUnauthenticated:
		return connect.CodeUnauthenticated
	case KindFailedPrecondition:
		return connect.CodeFailedPrecondition
	case KindPermissionDenied:
		return connect.CodePermissionDenied
	case KindUnimplemented:
		return connect.CodeUnimplemented
	case KindEntitlementMissing,
		KindEntitlementMalformed,
		KindEntitlementExpired,
		KindEntitlementWrongBuyer,
		KindSubscriptionLapsed,
		KindEntitlementNotGranted,
		KindEntitlementStaleAttenuation:
		return connect.CodeUnauthenticated
	default:
		return connect.CodeUnknown
	}
}

// Newf wraps a domain error with formatted message.
func Newf(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// Wrap wraps an existing cause with a domain error Kind.
func Wrap(kind Kind, cause error, msg string) *Error {
	return &Error{Kind: kind, Message: msg, Err: cause}
}

// ToConnect converts any error into a connect.Error, preserving Kind mapping
// when err is a *exchange.Error. Non-domain errors are surfaced as Internal.
func ToConnect(err error) *connect.Error {
	if err == nil {
		return nil
	}
	var de *Error
	if errors.As(err, &de) {
		return connect.NewError(de.Kind.ConnectCode(), de)
	}
	return connect.NewError(connect.CodeInternal, err)
}

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
	// (ADR-003 §5). Maps to connect.CodePermissionDenied.
	KindPermissionDenied
	// KindUnimplemented signals an operation the adapter or handler does not
	// implement — e.g. a billing adapter with no reverse-transfer primitive
	// returning ErrRefundUnsupported. Maps to connect.CodeUnimplemented.
	KindUnimplemented
	// Refusal-reason taxonomy (obligation 05). Each kind
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
	// KindOfferExpired signals that a presented offer's signature verified but
	// its signed expires_at is in the past (or absent — fail-closed). Distinct
	// from KindSignatureInvalid so the wire surfaces DENIAL_REASON_OFFER_EXPIRED
	// rather than mislabeling a stale-but-authentic offer as a signature failure.
	// Maps to connect.CodeUnauthenticated (the offer is no longer a valid bearer
	// credential), like the signature-invalid family.
	KindOfferExpired
	// KindUnavailable signals a transient upstream dependency failure (e.g.
	// the caller's /.well-known/ramp.json host is unreachable during ADR-009
	// D2 lazy registration). Distinct from KindInternal so the caller learns
	// the request is retryable rather than a server fault.
	KindUnavailable
	// KindAccountNotRegistered signals that a paid transaction came from an agent
	// with no billing_ref — it never registered, so it has no account to charge
	// (ADR-021 D5). A per-item business denial: it maps to the wire reason
	// DENIAL_REASON_BILLING_REF_INACTIVE, not a server fault.
	KindAccountNotRegistered
	// KindAccountInactive signals that a paid transaction came from a registered
	// agent whose account the operator switched off in the system of record (or
	// whose account the SoR does not know at all). Same wire reason as
	// KindAccountNotRegistered — DENIAL_REASON_BILLING_REF_INACTIVE — but a
	// distinct kind, so logs and messages keep "never registered" and
	// "registered but switched off" apart.
	KindAccountInactive
)

// Error is the canonical domain error. Handlers receive it from the service
// layer and convert it to a connect.Error at the boundary.
type Error struct {
	Kind    Kind
	Message string
	Err     error
	// Metadata carries structured, machine-readable context (e.g. the offending
	// field name) that the transport boundary stamps onto ErrorDetail.metadata
	// (ADR-019). It exists so callers stop baking such context into the
	// non-authoritative Message string. Optional; nil when there is none.
	Metadata map[string]string
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
	KindInvalidRequest:        "invalid_request",
	KindNotFound:              "not_found",
	KindSignatureInvalid:      "signature_invalid",
	KindBillingDenied:         "billing_denied",
	KindIdempotent:            "idempotent",
	KindInternal:              "internal",
	KindUnauthenticated:       "unauthenticated",
	KindFailedPrecondition:    "failed_precondition",
	KindPermissionDenied:      "permission_denied",
	KindUnimplemented:         "unimplemented",
	KindEntitlementMissing:    "entitlement_missing",
	KindEntitlementMalformed:  "entitlement_malformed",
	KindEntitlementExpired:    "entitlement_expired",
	KindEntitlementWrongBuyer: "entitlement_wrong_buyer",
	KindSubscriptionLapsed:    "subscription_lapsed",
	KindEntitlementNotGranted: "entitlement_not_granted",
	KindOfferExpired:          "offer_expired",
	KindUnavailable:           "unavailable",
	KindAccountNotRegistered:  "account_not_registered",
	KindAccountInactive:       "account_inactive",
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
	case KindBillingDenied, KindAccountNotRegistered, KindAccountInactive:
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
	case KindOfferExpired:
		return connect.CodeUnauthenticated
	case KindUnavailable:
		return connect.CodeUnavailable
	case KindEntitlementMissing,
		KindEntitlementMalformed,
		KindEntitlementExpired,
		KindEntitlementWrongBuyer,
		KindSubscriptionLapsed,
		KindEntitlementNotGranted:
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

// WithField records the offending field name as structured Metadata so the
// transport boundary can stamp it onto ErrorDetail.metadata["field"] (ADR-019),
// rather than embedding it in the non-authoritative Message string. Returns the
// receiver for fluent chaining off Newf/Wrap.
func (e *Error) WithField(name string) *Error {
	if e.Metadata == nil {
		e.Metadata = make(map[string]string, 1)
	}
	e.Metadata["field"] = name
	return e
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

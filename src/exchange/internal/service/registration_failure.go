package service

import (
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// registrationFailureByKind maps the Exchange's registration-refusal kinds onto
// the canonical proto RegistrationFailureReason vocabulary (ADR-019). Only kinds
// that represent a refused registration appear here; every other Register
// failure — the payload bounds, an unseeded default tenant, a SoR, ledger or
// internal fault — is absent and carries only a transport code plus the shared
// reasonless ErrorDetail envelope.
//
// This is the SINGLE source of truth for the registration-failure vocabulary,
// the twin of denialReasonByKind for the denial vocabulary.
var registrationFailureByKind = map[exchange.Kind]rampv1.RegistrationFailureReason{
	exchange.KindRegistrationDataInvalid: reasonInvalidRegistrationData,
	exchange.KindTermsDigestStale:        reasonTermsDigestStale,
}

// The registration-failure reasons this package names. Two of them are the map
// above; reasonUnspecified is not, and is what RegistrationFailureForError
// reports when the error carries no reason at all.
//
// They are aliased as a set rather than one at a time. Only the
// INVALID_REGISTRATION_DATA spelling is actually too long for the line limit —
// the other two fit — but a block where one constant is short and its two
// siblings are written out in full reads as though the difference meant
// something. It does not.
const (
	reasonUnspecified             = rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_UNSPECIFIED
	reasonInvalidRegistrationData = rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA
	reasonTermsDigestStale        = rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE
)

// registrationFailure carries the per-field list a schema refusal produces
// alongside the domain error. The list is built from proto messages, so it
// cannot live on exchange.Error: that package is deliberately protobuf-free, and
// the service layer is where the Exchange's kinds meet the wire vocabulary — the
// same division denial.go draws.
//
// It wraps rather than embeds the domain error. Unwrap returns the *exchange.Error
// itself, so errors.As still finds it and exchange.ToConnect still maps the kind
// to its connect.Code; an embedded pointer would promote Unwrap and hide the
// domain error behind its own cause.
//
// NEITHER constructor below stamps field metadata on the wrapped domain error,
// and that is deliberate rather than an omission. On this typed path the reason
// oneof IS the machine-readable payload: a schema refusal carries the per-member
// field_errors list, which names the offending members more precisely than a
// single field name could, and a stale digest carries TERMS_DIGEST_STALE, which
// identifies the field by naming the condition. The envelope is built by
// helpers.RegistrationFailureDetail, which carries no metadata map at all, so a
// field set here would be computed and then dropped.
//
// So Register answers a bounds refusal with metadata["field"] =
// "registration_data" and a schema refusal with no metadata, and that difference
// is the intended shape. A bounds refusal carries no reason — it is a malformed
// request, not non-conformance to a published schema — so it routes through the
// reasonless generic envelope, and that envelope is the only one metadata rides.
type registrationFailure struct {
	err         *exchange.Error
	fieldErrors []*rampv1.RegistrationFieldError
}

// Error renders the wrapped domain error unchanged. The field list is
// machine-readable detail and never joins the message.
func (f *registrationFailure) Error() string { return f.err.Error() }

// Unwrap exposes the domain error for errors.As and exchange.ToConnect.
func (f *registrationFailure) Unwrap() error { return f.err }

// registrationDataInvalid refuses a payload that does not conform to the schema
// the Exchange publishes, carrying the per-field list the SDK validator produced.
//
// This is the ONLY constructor that sets fieldErrors, and it is the only one that
// uses KindRegistrationDataInvalid. That pairing is what keeps the proto's CEL
// rule — field_errors is legal only alongside INVALID_REGISTRATION_DATA — true by
// construction rather than by a check at the transport.
//
// The list is passed through as the SDK returned it: the SDK deduplicates, sorts
// by path then keyword, caps at 64 entries, and never echoes a submitted value.
// None of that is re-derived here.
func registrationDataInvalid(fieldErrors []*rampv1.RegistrationFieldError) error {
	return &registrationFailure{
		err: exchange.Newf(exchange.KindRegistrationDataInvalid,
			"registration_data does not conform to the published data_schema: %d field(s) failed",
			len(fieldErrors)),
		fieldErrors: fieldErrors,
	}
}

// termsDigestStale refuses a registration whose terms_digest is not the digest
// the Exchange currently publishes. It carries no field list: the proto allows
// field_errors only with INVALID_REGISTRATION_DATA.
//
// The published digest is named in the message because it is public — the
// manifest serves it to anyone — and naming it tells the caller exactly what to
// hash against. The submitted digest is not echoed.
func termsDigestStale(published string) error {
	return &registrationFailure{
		err: exchange.Newf(exchange.KindTermsDigestStale,
			"terms_digest does not match the published digest %s: re-fetch the terms and register again",
			published),
	}
}

// RegistrationFailureForError returns the canonical RegistrationFailureReason for
// a refused registration plus any per-field list it carries, or ok=false when the
// failure carries no reason. It is the twin of DenialReasonForKind: the transport
// layer's registerError calls it, and a false ok routes the error through the
// shared reasonless fault envelope instead.
func RegistrationFailureForError(err error) (rampv1.RegistrationFailureReason, []*rampv1.RegistrationFieldError, bool) {
	var de *exchange.Error
	if !errors.As(err, &de) {
		return reasonUnspecified, nil, false
	}
	reason, ok := registrationFailureByKind[de.Kind]
	if !ok {
		return reasonUnspecified, nil, false
	}
	var f *registrationFailure
	if errors.As(err, &f) {
		return reason, f.fieldErrors, true
	}
	return reason, nil, true
}

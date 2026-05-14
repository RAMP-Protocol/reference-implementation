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

// String renders Kind for logging.
func (k Kind) String() string {
	switch k {
	case KindInvalidRequest:
		return "invalid_request"
	case KindNotFound:
		return "not_found"
	case KindSignatureInvalid:
		return "signature_invalid"
	case KindBillingDenied:
		return "billing_denied"
	case KindIdempotent:
		return "idempotent"
	case KindInternal:
		return "internal"
	default:
		return "unspecified"
	}
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
// when err is a *exchange.Error. Only Kind + Message are sent over the wire;
// the wrapped cause (which may contain DSN fragments or SQL detail) is never
// forwarded to callers. Non-domain errors surface as generic Internal.
func ToConnect(err error) *connect.Error {
	if err == nil {
		return nil
	}
	var de *Error
	if errors.As(err, &de) {
		return connect.NewError(de.Kind.ConnectCode(), errors.New(de.Message))
	}
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

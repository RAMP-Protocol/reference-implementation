// Package broker owns the Broker domain error type. Transport layers map
// broker.Error to the appropriate Connect-Go code or HTTP status.
package broker

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"
)

// Kind classifies the domain error for transport mapping.
type Kind int

// Error kinds. Keep in sync with the mapping in ConnectCode below.
const (
	KindUnknown Kind = iota
	KindInvalidArgument
	KindNotFound
	KindUnauthenticated
	KindPermissionDenied
	KindBudgetExhausted
	KindUpstreamUnavailable
	KindUpstreamRejected
	KindInternal
)

// Error is the canonical Broker domain error.
type Error struct {
	Kind    Kind
	Message string
	Err     error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Kind, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

// Unwrap exposes the wrapped cause for errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.Err }

// Newf constructs a broker.Error with a formatted message.
func Newf(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// Wrapf wraps an existing error with a kind and message.
func Wrapf(kind Kind, err error, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...), Err: err}
}

// String renders Kind for logging.
func (k Kind) String() string {
	switch k {
	case KindInvalidArgument:
		return "invalid_argument"
	case KindNotFound:
		return "not_found"
	case KindUnauthenticated:
		return "unauthenticated"
	case KindPermissionDenied:
		return "permission_denied"
	case KindBudgetExhausted:
		return "budget_exhausted"
	case KindUpstreamUnavailable:
		return "upstream_unavailable"
	case KindUpstreamRejected:
		return "upstream_rejected"
	case KindInternal:
		return "internal"
	default:
		return "unknown"
	}
}

// ConnectCode maps a Kind to a Connect-Go code for transport.
func (k Kind) ConnectCode() connect.Code {
	switch k {
	case KindInvalidArgument:
		return connect.CodeInvalidArgument
	case KindNotFound:
		return connect.CodeNotFound
	case KindUnauthenticated:
		return connect.CodeUnauthenticated
	case KindPermissionDenied:
		return connect.CodePermissionDenied
	case KindBudgetExhausted:
		return connect.CodeResourceExhausted
	case KindUpstreamUnavailable:
		return connect.CodeUnavailable
	case KindUpstreamRejected:
		return connect.CodeFailedPrecondition
	default:
		return connect.CodeInternal
	}
}

// ToConnect converts any error to a connect.Error. If err wraps a broker.Error
// the Kind is honored; otherwise it is treated as internal.
func ToConnect(err error) error {
	if err == nil {
		return nil
	}
	var be *Error
	if errors.As(err, &be) {
		return connect.NewError(be.Kind.ConnectCode(), be)
	}
	return connect.NewError(connect.CodeInternal, err)
}

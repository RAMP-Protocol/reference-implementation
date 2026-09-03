package testutil

import (
	"errors"
	"testing"

	validate "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	protovalidate "buf.build/go/protovalidate"
	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// detailsOf decodes every typed error detail of one message type attached to a
// connect error.
//
// It is the walk both faces below need and neither owns: unwrap to a
// *connect.Error, range the attached details, decode each, and skip the ones
// that decode to some other message. Only the message type varies, so it is the
// type parameter; what the caller does with the result — require exactly one,
// accept zero or more, flatten a container — stays at the call site, which is
// where those policies differ.
func detailsOf[T proto.Message](tb testing.TB, err error) []T {
	tb.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		tb.Fatalf("error is %T, want *connect.Error: %v", err, err)
	}
	attached := ce.Details()
	found := make([]T, 0, len(attached))
	for _, d := range attached {
		msg, valueErr := d.Value()
		if valueErr != nil {
			continue
		}
		if typed, ok := msg.(T); ok {
			found = append(found, typed)
		}
	}
	return found
}

// ErrorDetails decodes every rampv1.ErrorDetail attached to a connect error.
//
// Zero is a valid answer, and that is the reason this reader is separate from
// SingleErrorDetail below. A request the validation interceptor refuses never
// reaches the code that builds a RAMP envelope, so it carries protovalidate's
// own violation detail and no ErrorDetail at all. A test asserting that outcome
// needs a reader that returns an empty slice rather than one that fails.
//
// Two policies sit on top of it: SingleErrorDetail requires exactly one
// envelope, and a caller that ranges over the returned slice accepts zero or
// more. ValidationViolations below reads a different message — protovalidate's
// Violations, which arrives as a CONTAINER holding the list rather than as one
// detail per violation — so it flattens where this one collects. The walk under
// both is detailsOf above; only the message type and the flattening differ. The
// one hand-written walk left anywhere else is in the identity MCP error mapper,
// which is PRODUCTION code and cannot use a helper that fails a test.
//
// It takes a plain error and unwraps it in detailsOf, because no caller holds a
// *connect.Error already: every one of them starts from what an RPC or an error
// mapper returned. Taking the narrower type only moved the same four-line
// errors.As preamble into all of them.
//
// It is in repo-wide testutil as a deliberate choice, not because of a Go
// visibility rule. An exported identifier in an in-package _test.go file IS
// visible to that directory's external test package — the standard
// export_test.go pattern — so a package-local definition would have reached the
// exchange callers. It is here because the envelope it decodes is the shared
// RAMP fault shape rather than anything exchange-specific, and its callers are
// spread across the exchange transport, the broker transport and the audience
// interceptor.
func ErrorDetails(tb testing.TB, err error) []*rampv1.ErrorDetail {
	tb.Helper()
	return detailsOf[*rampv1.ErrorDetail](tb, err)
}

// SingleErrorDetail decodes the exactly-one rampv1.ErrorDetail attached to a
// connect error, failing the test when there is none or more than one.
//
// "Exactly one" is part of what it checks, not an assumption. Every RAMP fault
// builds its envelope in one place, so a second detail means two builders ran
// over the same error and a client reading the first would get a different
// answer from one reading the last.
func SingleErrorDetail(tb testing.TB, err error) *rampv1.ErrorDetail {
	tb.Helper()
	found := ErrorDetails(tb, err)
	switch len(found) {
	case 1:
		return found[0]
	case 0:
		tb.Fatalf("no rampv1.ErrorDetail attached to error: %v", err)
	default:
		tb.Fatalf("%d ErrorDetails attached; the envelope must be built exactly once", len(found))
	}
	return nil
}

// ValidationViolations decodes the buf.validate.Violations detail the validate
// interceptor (connectrpc.com/validate, which the SDK's strict validation
// composes) attaches when it refuses a request at the wire tier.
//
// Zero is a valid answer, for the reason ErrorDetails gives above in reverse: a
// request the wire tier admits and a later gate refuses carries a RAMP
// ErrorDetail and no Violations. A test proving WHICH tier refused reads that
// absence as much as the presence, since every tier answers InvalidArgument.
func ValidationViolations(tb testing.TB, err error) []*validate.Violation {
	tb.Helper()
	var found []*validate.Violation
	for _, container := range detailsOf[*validate.Violations](tb, err) {
		found = append(found, container.GetViolations()...)
	}
	return found
}

// ViolationFieldPath renders a violation's field path the way protovalidate's
// own messages do — entries[0].terms — so a test names the field a wire refusal
// is about without walking the path elements itself. A list element carries its
// index, a map entry its key.
//
// The rendering is protovalidate's own FieldPathString, not a copy of it. The
// SDK builds every RuleViolation.Path with that function, so a test that
// rendered the path itself would be comparing two spellings of one path and
// would drift the moment the library added a subscript kind.
func ViolationFieldPath(v *validate.Violation) string {
	return protovalidate.FieldPathString(v.GetField())
}

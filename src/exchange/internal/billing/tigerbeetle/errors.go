package tigerbeetle

import "errors"

// Sentinel errors for the connection layer. Callers use errors.Is; the adapter maps
// these to the billing/exchange error hierarchy at the adapter boundary.
var (
	// ErrEmptyID is returned by the id helpers when the business id (or
	// idempotency key) is empty — there is no meaningful id to derive.
	ErrEmptyID = errors.New("tigerbeetle: empty business id")

	// ErrReservedID is returned when a derived id lands on one of TigerBeetle's
	// two reserved values (0 or 2^128-1). Astronomically unlikely for a sha256
	// slice, but the id contract forbids both, so the helper refuses to emit them.
	ErrReservedID = errors.New("tigerbeetle: derived id is reserved (0 or 2^128-1)")

	// ErrAccountConflict is returned by EnsureAccount when the id already exists
	// with different fields (flags/code/ledger/user_data) — a real conflict, not
	// the idempotent identical-account case.
	ErrAccountConflict = errors.New("tigerbeetle: account exists with different fields")

	// ErrCreateAccount is returned by EnsureAccount for any other non-ok create
	// status (validation failures, etc.).
	ErrCreateAccount = errors.New("tigerbeetle: create account failed")

	// ErrCreateTransfer is returned by the transfer primitives for a create status
	// that is neither success, a benign duplicate, nor a mapped lifecycle outcome
	// (e.g. a validation failure).
	ErrCreateTransfer = errors.New("tigerbeetle: create transfer failed")

	// ErrBadID is returned by DecodeID when a string is not a 16-byte hex id.
	ErrBadID = errors.New("tigerbeetle: malformed id")

	// ErrAmountNotRepresentable is returned by MinorUnits when a value has finer
	// precision than the ledger's asset scale can represent exactly — converting
	// it would require rounding, so the converter refuses it rather than silently
	// truncate a money amount.
	ErrAmountNotRepresentable = errors.New("tigerbeetle: amount not representable at asset scale")

	// ErrUnavailable is returned when the cluster does not answer within the
	// per-call deadline — from Health, or from any bounded hot-path call whose
	// deadline elapses. The tigerbeetle-go client is not context-cancelable and
	// blocks indefinitely on an unreachable cluster, so a bounded call reports
	// this rather than wedging the caller. It is the retryable "backend
	// unavailable" signal the adapter maps to a 503-class code.
	ErrUnavailable = errors.New("tigerbeetle: cluster unavailable")
)

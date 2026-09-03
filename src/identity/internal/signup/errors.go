package signup

import "errors"

// ErrSlugExhausted means the registry could not mint a free subdomain after several
// attempts — every candidate collided with an existing one. It is an internal fault
// (a 500), not a caller error; in practice it never fires, because an 8-character
// random slug space does not fill.
//
// It is the only sentinel this package defines for a running sign-up. Every other
// failure SignIn returns comes from one of its dependencies — the slug generator,
// the keystore, the account store, the card store — wrapped with %w for context.
// A dependency that defines a sentinel therefore still matches through the wrap,
// which is how a caller turns keystore.ErrUnavailable into a 503; where there is
// no sentinel to match — RandomSlugGen's entropy failure is the one this package
// itself produces — the wrapped error stays a plain internal fault. Either way the
// failure was decided elsewhere, and a sentinel minted here would only rename it.
//
// New is the exception, and it needs no sentinel: it rejects an incomplete Config
// with plain errors that nothing matches on, because a missing dependency is a
// wiring fault the process cannot start from.
var ErrSlugExhausted = errors.New("signup: could not mint a free subdomain")

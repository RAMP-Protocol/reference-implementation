// Package signup owns the developer sign-up act: on a verified upstream sign-in it
// mints the agent's subdomain, key, and card, and it validates and stores the three
// mandatory licensing-deal fields the registration form collects. It sits above
// custody (keystore) and persistence (the account/card stores) and depends on them
// through narrow ports, so its policy is unit-testable with fakes and its wiring is
// integration-tested through the HTTP surface.
package signup

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrSlugExhausted means the registry could not mint a free subdomain after several
// attempts — every candidate collided with an existing one. It is an internal fault
// (a 500), not a caller error; in practice it never fires, because an 8-character
// random slug space does not fill.
var ErrSlugExhausted = errors.New("signup: could not mint a free subdomain")

// FormInput is the raw registration form submission: the three licensing-deal
// fields a licensing agreement needs and the WBA card cannot carry. The field names
// match the domain, sqlc, and DB column (JurisdictionCountry) end to end.
type FormInput struct {
	LegalEntity         string
	Address             string
	JurisdictionCountry string
}

// ValidationError collects one message per rejected field so the form re-renders
// every problem at once rather than surfacing them one submit at a time. It is a
// value error (a 400-class outcome the form owns), never logged as a server fault.
type ValidationError struct {
	Fields map[string]string
}

// Error renders the collected field errors in a stable order (sorted by field name)
// so the message is deterministic in tests and logs.
func (e *ValidationError) Error() string {
	names := make([]string, 0, len(e.Fields))
	for name := range e.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s: %s", name, e.Fields[name]))
	}
	return "signup: invalid registration form (" + strings.Join(parts, "; ") + ")"
}

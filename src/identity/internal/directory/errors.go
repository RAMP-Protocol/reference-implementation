package directory

import "errors"

// ErrCardNotFound is the CardReader contract's sentinel for "this subdomain has no
// card". It lives with the port, not the store, so the serving layer can interpret
// a lookup result without importing the persistence package. The Postgres repo
// returns it (wrapping pgx.ErrNoRows); the publisher treats it as an absent card.
//
// This package otherwise reports build failures as plainly-wrapped errors, matching
// the sentinel style the sibling keystore package uses inside this service: the two
// build faults (an empty key set, a marshal error) are always internal server
// faults, so a kind enum that mapped every one of them to the same status would be
// classification with no reader.
var ErrCardNotFound = errors.New("directory: card not found")

// ErrCardUnavailable is the CardReader contract's sentinel for a transient store
// outage (connection refused, too many connections, admin shutdown, a cancelled
// context). It is distinct from ErrCardNotFound so the publisher can answer a blip
// with a retryable 503 instead of a permanent-looking 500 — the same distinction
// the keystore draws with ErrUnavailable.
var ErrCardUnavailable = errors.New("directory: card store unavailable")

// ErrRevocationUnavailable is the RevocationReader contract's sentinel for a
// transient revocation-store outage, distinct so the publisher answers a blip with a
// retryable 503 rather than a 500. There is deliberately no "not found" companion: a
// subdomain with no revocation row is the epoch-dated empty baseline — a valid
// document, not an absence — so the reader returns that, never an error.
var ErrRevocationUnavailable = errors.New("directory: revocation store unavailable")

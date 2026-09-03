// Package account holds the developer-account domain type and its store contract:
// the durable link a developer sign-up creates between the OIDC identity a person
// authenticates as and the agent subdomain the registry mints for them. It is a
// thin domain package (types + error sentinels, no I/O); the Postgres
// implementation lives in the repo package, and the sign-up service depends on the
// Store interface here.
package account

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// Developer is one developer account keyed on its OIDC identity (issuer + subject).
// Subdomain is the agent identity the registry minted for it — stable across the
// developer's future key rotations.
//
// It carries no business data about the operator behind the account. It once held
// a legal entity, an address and a jurisdiction, collected by a sign-up form and
// forwarded as registration_data when an agent opened an Exchange account. That
// call now carries the fields the AGENT supplies, per Exchange, so this service
// neither needs them nor keeps them.
type Developer struct {
	Issuer    string
	Subject   string
	Email     string
	Subdomain string
}

// ExchangeRegistration is one local note that this service registered an agent
// at an Exchange: which Exchange, and when the registration was last confirmed.
//
// It carries no part of what was submitted, and that is the point rather than an
// omission — the registration details are the operator's business data and this
// service does not keep them. The migration that creates the table states the
// same thing, at length, beside the columns.
//
// It is a HINT. The Exchange is the only party that knows whether an account
// exists; a registration made outside this adapter leaves no note, and a note
// can outlive an account the Exchange closed.
type ExchangeRegistration struct {
	Exchange     string
	RegisteredAt time.Time
}

// Requirements is what one Exchange asks of a registration, as of the fetch that
// produced it: the schema its registration_data must match, and the terms
// revision that submitting one accepts.
//
// It lives here, beside ExchangeRegistration, rather than in the package that
// reads it. A consumer that named the reader's own result type would have its
// contract defined inside the adapter it depends on, and the two packages could
// not then be separated. Same reason RegistrationLog is here and not in repo.
type Requirements struct {
	// TermsDigest is the manifest's terms_digest, nil when the Exchange
	// publishes none. It is copied onto RegisterRequest.terms_digest unchanged,
	// where the request signature covers it and the Exchange records it as the
	// revision the operator accepted.
	TermsDigest *string

	// Schema validates registration_data before anything is signed.
	//
	// It is nil in TWO cases, and Verdict is what tells them apart: the Exchange
	// publishes no schema, and the Exchange publishes one this service cannot
	// use. Both are deliberately the same VALUE, because a nil
	// *RegistrationSchema reports no failures and that is the behaviour the SDK
	// requires of a client in both cases. A local check that cannot run must not
	// become a local veto: the Exchange's own check is the deciding one, and a
	// client that refused here would block a registration the Exchange would
	// have accepted, with no way for the agent to get past it.
	Schema *helpers.RegistrationSchema

	// Verdict is the SDK's answer for the published schema. SchemaNotPublished
	// is the normal absent case; SchemaAccepted means Schema is usable; anything
	// else names why a published schema was refused, which is worth logging and
	// is never worth refusing the registration over.
	Verdict helpers.SchemaVerdict
}

// SchemaRefused reports whether the Exchange published a schema this service
// could not use. That is the state worth a log line: the agent is about to
// register with no local pre-check against requirements that do exist.
func (r Requirements) SchemaRefused() bool {
	return r.Verdict != helpers.SchemaAccepted && r.Verdict != helpers.SchemaNotPublished
}

// MaxExchangeRegistrations is how many notes one agent may accumulate.
//
// The exchange half of the key is a value an authenticated agent chooses per
// call, and with no allowlist configured — which the deployment documentation
// describes as the normal case — the key space is the whole DNS namespace. So
// this is a caller-influenced store, and it is bounded for the same reason every
// in-memory one in this service is: somewhere a caller can make the process grow
// is somewhere a caller will.
//
// 64 rather than a number tuned to anything: an agent doing real business
// registers at a handful of Exchanges, so the cap is far above the honest case
// and small enough that the worst case is a bounded row count per agent rather
// than an unbounded one. Recording past it drops that agent's oldest notes, and
// a note is a hint the next status call rebuilds, so losing the oldest costs the
// agent nothing it cannot ask for again.
const MaxExchangeRegistrations = 64

// RegistrationLog records and reads those notes. It is a separate port from
// Store rather than more methods on it: Store is the developer identity a
// sign-up creates, and this is a per-agent list of who it does business with —
// different data with a different lifetime and a different reader.
type RegistrationLog interface {
	// Record notes that subdomain registered at exchange, at. Repeating a note
	// refreshes its timestamp rather than adding a second row, and recording
	// past MaxExchangeRegistrations drops that agent's oldest notes.
	Record(ctx context.Context, subdomain, exchange string, at time.Time) error
	// Forget drops the note for one Exchange. It is called when the Exchange
	// itself reports no account: a note the authority has just contradicted is
	// known-false rather than merely stale, and leaving it would have the
	// no-argument status call keep listing an account that does not exist.
	Forget(ctx context.Context, subdomain, exchange string) error
	// List returns subdomain's notes, ordered by Exchange domain, at most
	// MaxExchangeRegistrations of them. An agent with none gets an empty list,
	// never an error — having registered nowhere is a normal state.
	List(ctx context.Context, subdomain string) ([]ExchangeRegistration, error)
}

// CanonicalExchange renders every spelling of one Exchange identity as one
// string. It is what this service compares and stores.
//
// It answers the PARTY question: do two values name the same Exchange? So it
// folds the two differences the protocol folds, and only those.
//
// Case, because domain names are case-insensitive. An agent writing
// Exchange.Example and one writing exchange.example name the same host, and the
// receiving Exchange lowercases the host before checking the audience its
// signature claims.
//
// A written-out :443, because a schemeless domain is read as https throughout
// the protocol SDK, so 443 spelled out and 443 left implicit are one port. The
// SDK's audience check folds it when deciding whether two spellings name the
// same party, and the endpoint anchor folds it when deciding where that party
// lives. Both spellings therefore reach one account at one Exchange. Any other
// port is kept, 80 included: folding that would read a scheme into a value that
// names none.
//
// Without the port fold the note store is the place the two spellings come
// apart. Its key is (subdomain, exchange) over plain text, so one Exchange
// becomes two rows, a forget on one spelling cannot remove the other, and the
// hint list names one Exchange twice.
//
// Only a value helpers.IsBareDomain accepts is folded. Canonicalising is not
// narrowing: a malformed value comes out exactly as it arrived, so the shape
// rule still sees what the caller wrote rather than something repaired on the
// way. The port split below is safe for the same reason — on a value that rule
// has accepted, a colon is a port separator and nothing else.
//
// The deployment's allowlist deliberately does NOT compare through this
// function. It answers a different question — did an operator list this value —
// and reads their list as written. See exchpolicy.
func CanonicalExchange(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !helpers.IsBareDomain(domain) {
		return domain
	}
	host, port, found := strings.Cut(domain, ":")
	if !found || port == "443" {
		return host
	}
	return domain
}

// ErrNotBareDomain reports a value that is not the shape a domain-valued field
// admits. It is a sentinel rather than a bare message so a caller can tell a
// refused ARGUMENT from a peer that would not answer, and render the two
// differently.
//
// It lives here for the reason ErrNoAccount does: it is part of what the
// requirements leg promises its consumer, not one implementation's private
// vocabulary. A service depending on that leg through a narrow interface must be
// able to name this without importing the concrete reader that produces it.
var ErrNotBareDomain = errors.New("account: exchange must be a bare domain, not a URL")

// ErrNotPermitted reports a domain this deployment's Exchange policy excludes.
// The refusal happens before any fetch, so an excluded domain is never dialled.
//
// Declared beside ErrNotBareDomain and for the same reason: a caller has to tell
// "this deployment will not speak to that Exchange" from "that Exchange did not
// answer", and the two have different remedies — one is the operator's setting,
// the other is the peer.
var ErrNotPermitted = errors.New("account: exchange not permitted by this deployment")

// ErrNoAccount reports an Exchange's answer that an agent holds no account
// there. It is a normal outcome rather than a failure, and a caller works it out
// with errors.Is.
//
// It is declared beside the ports rather than inside the outbound client that
// classifies it. "No account at this Exchange" is part of what the account leg
// promises its consumer — it is the answer that makes a status call report
// "registered: false" and drop the local note — so a service depending on that
// leg through a narrow interface must not have to import a concrete client to
// name it. The client that turns a wire answer into this value stays free to be
// replaced, which the outbound package's own plan requires: it goes when the two
// account RPCs land in the SDK, and a sentinel defined there would go with it.
var ErrNoAccount = errors.New("account: no account at this exchange")

// Store is the persistence port the sign-up service depends on (interface
// segregation, mirroring directory.CardReader). *repo.PgxDeveloperRepo satisfies it.
type Store interface {
	// BySubject resolves a developer by its OIDC identity, or ErrNotFound.
	BySubject(ctx context.Context, issuer, subject string) (Developer, error)
	// Reserve creates the account row that claims subdomain for (issuer, subject).
	// It returns ErrSubdomainTaken when the subdomain is already claimed (the
	// sign-up retries with a fresh slug) and ErrAlreadyExists when this OIDC
	// identity already has an account (a concurrent sign-in won the race; re-read
	// BySubject).
	Reserve(ctx context.Context, d Developer) (Developer, error)
}

// Domain sentinels the Store maps its persistence errors onto, so the sign-up
// service reasons about outcomes without importing pgx. ErrUnavailable marks a
// transient store outage (retryable), distinct from a definite result.
var (
	ErrNotFound       = errors.New("account: developer not found")
	ErrSubdomainTaken = errors.New("account: subdomain already claimed")
	ErrAlreadyExists  = errors.New("account: developer already exists")
	ErrUnavailable    = errors.New("account: store unavailable")
)

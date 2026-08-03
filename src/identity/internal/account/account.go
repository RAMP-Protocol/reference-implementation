// Package account holds the developer-account domain type and its store contract:
// the durable link a developer sign-up creates between the OIDC identity a person
// authenticates as and the agent subdomain the registry mints for them, plus the
// three licensing-deal fields the sign-up form collects. It is a thin domain
// package (types + error sentinels, no I/O); the Postgres implementation lives in
// the repo package, and the sign-up service depends on the Store interface here.
package account

import (
	"context"
	"errors"
)

// Developer is one developer account keyed on its OIDC identity (issuer + subject).
// Subdomain is the agent identity the registry minted for it — stable across the
// developer's future key rotations. The three licensing fields are empty until the
// mandatory registration form is submitted, at which point RegistrationComplete
// flips true; that flag is the sign-up gate.
type Developer struct {
	Issuer               string
	Subject              string
	Email                string
	Subdomain            string
	LegalEntity          string
	Address              string
	JurisdictionCountry  string
	RegistrationComplete bool
}

// LicensingDetails is the trio of mandatory licensing-deal fields the
// registration form collects. It is passed as one value (not three positional
// strings) so the fields cannot be silently transposed at a call site.
type LicensingDetails struct {
	LegalEntity         string
	Address             string
	JurisdictionCountry string
}

// Store is the persistence port the sign-up service depends on (interface
// segregation, mirroring directory.CardReader). *repo.PgxDeveloperRepo satisfies it.
type Store interface {
	// BySubject resolves a developer by its OIDC identity, or ErrNotFound.
	BySubject(ctx context.Context, issuer, subject string) (Developer, error)
	// BySubdomain resolves a developer by its minted subdomain, or ErrNotFound. It
	// is the read-back path a later Register step uses to forward the licensing
	// fields as registration_data.
	BySubdomain(ctx context.Context, subdomain string) (Developer, error)
	// Reserve creates the account row that claims subdomain for (issuer, subject),
	// with the licensing fields still empty and RegistrationComplete false. It
	// returns ErrSubdomainTaken when the subdomain is already claimed (the sign-up
	// retries with a fresh slug) and ErrAlreadyExists when this OIDC identity
	// already has an account (a concurrent sign-in won the race; re-read BySubject).
	Reserve(ctx context.Context, d Developer) (Developer, error)
	// CompleteRegistration stores the three licensing fields and flips
	// RegistrationComplete true for (issuer, subject), or ErrNotFound if the
	// account row is gone.
	CompleteRegistration(ctx context.Context, issuer, subject string, d LicensingDetails) (Developer, error)
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

package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/db/sqlc"
)

// Constraint names from migration 000004's developer_account table. Reserve keys
// its outcome off these so it can tell "this slug is taken" (retry with a new one)
// apart from "this OIDC identity already signed up" (a concurrent winner; re-read).
const (
	developerSubdomainConstraint = "developer_account_subdomain_unique"
	developerPKConstraint        = "developer_account_pkey"
)

// PgxDeveloperRepo backs account.Store over the sqlc Querier.
type PgxDeveloperRepo struct {
	q *sqlc.Queries
}

// NewDeveloperRepo constructs a developer-account repo over the given pool.
func NewDeveloperRepo(pool *pgxpool.Pool) *PgxDeveloperRepo {
	return &PgxDeveloperRepo{q: sqlc.New(pool)}
}

// BySubject resolves a developer by its OIDC identity, translating pgx.ErrNoRows to
// account.ErrNotFound and a store outage to account.ErrUnavailable.
func (r *PgxDeveloperRepo) BySubject(ctx context.Context, issuer, subject string) (account.Developer, error) {
	row, err := r.q.GetDeveloperBySubject(ctx, sqlc.GetDeveloperBySubjectParams{
		OidcIssuer:  issuer,
		OidcSubject: subject,
	})
	if err != nil {
		return account.Developer{}, mapReadErr(err, account.ErrNotFound, account.ErrUnavailable,
			fmt.Sprintf("developer subject %q/%q", issuer, subject))
	}
	return toDeveloper(row), nil
}

// BySubdomain resolves a developer by its minted subdomain — the read-back path a
// later Register step uses to forward the licensing fields.
func (r *PgxDeveloperRepo) BySubdomain(ctx context.Context, subdomain string) (account.Developer, error) {
	row, err := r.q.GetDeveloperBySubdomain(ctx, subdomain)
	if err != nil {
		return account.Developer{}, mapReadErr(err, account.ErrNotFound, account.ErrUnavailable,
			fmt.Sprintf("developer subdomain %q", subdomain))
	}
	return toDeveloper(row), nil
}

// Reserve inserts the account row that claims d.Subdomain for (d.Issuer, d.Subject).
// A unique violation is classified by constraint: the subdomain constraint means the
// slug is taken (ErrSubdomainTaken), the primary key means this identity already has
// an account (ErrAlreadyExists).
func (r *PgxDeveloperRepo) Reserve(ctx context.Context, d account.Developer) (account.Developer, error) {
	row, err := r.q.ReserveDeveloper(ctx, sqlc.ReserveDeveloperParams{
		OidcIssuer:  d.Issuer,
		OidcSubject: d.Subject,
		Email:       d.Email,
		Subdomain:   d.Subdomain,
	})
	if err != nil {
		switch uniqueConstraint(err) {
		case developerSubdomainConstraint:
			return account.Developer{}, account.ErrSubdomainTaken
		case developerPKConstraint:
			return account.Developer{}, account.ErrAlreadyExists
		}
		return account.Developer{}, mapWriteErr(err, account.ErrUnavailable,
			fmt.Sprintf("reserve developer %q", d.Subdomain))
	}
	return toDeveloper(row), nil
}

// CompleteRegistration stores the three licensing fields and flips
// registration_complete for (issuer, subject).
func (r *PgxDeveloperRepo) CompleteRegistration(
	ctx context.Context, issuer, subject string, d account.LicensingDetails,
) (account.Developer, error) {
	row, err := r.q.CompleteDeveloperRegistration(ctx, sqlc.CompleteDeveloperRegistrationParams{
		OidcIssuer:          issuer,
		OidcSubject:         subject,
		LegalEntity:         d.LegalEntity,
		Address:             d.Address,
		JurisdictionCountry: d.JurisdictionCountry,
	})
	if err != nil {
		return account.Developer{}, mapReadErr(err, account.ErrNotFound, account.ErrUnavailable,
			fmt.Sprintf("complete developer %q/%q", issuer, subject))
	}
	return toDeveloper(row), nil
}

// mapReadErr translates a read/update persistence error to domain sentinels: no
// row to notFound, a transient outage to unavailable, anything else wrapped with
// context. Shared by the developer, oauth, and card repos so the same mapping is
// not re-inlined per read path.
func mapReadErr(err error, notFound, unavailable error, what string) error {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return notFound
	case isUnavailable(err):
		return unavailable
	default:
		return fmt.Errorf("%s: %w", what, err)
	}
}

// mapWriteErr translates a write persistence error: a transient outage to the given
// unavailable sentinel, anything else wrapped with context. Unlike mapReadErr there
// is no not-found case — a write does not "miss" a row. Callers return their zero
// value alongside it. Shared by the developer and oauth write paths so the outage
// mapping is not re-inlined per write.
func mapWriteErr(err error, unavailable error, what string) error {
	if isUnavailable(err) {
		return unavailable
	}
	return fmt.Errorf("%s: %w", what, err)
}

// uniqueConstraint returns the constraint name of a unique-violation (SQLSTATE
// 23505) error, or "" when err is not a unique violation.
func uniqueConstraint(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return pe.ConstraintName
	}
	return ""
}

func toDeveloper(row sqlc.IdentityDeveloperAccount) account.Developer {
	return account.Developer{
		Issuer:               row.OidcIssuer,
		Subject:              row.OidcSubject,
		Email:                row.Email,
		Subdomain:            row.Subdomain,
		LegalEntity:          row.LegalEntity,
		Address:              row.Address,
		JurisdictionCountry:  row.JurisdictionCountry,
		RegistrationComplete: row.RegistrationComplete,
	}
}

var _ account.Store = (*PgxDeveloperRepo)(nil)

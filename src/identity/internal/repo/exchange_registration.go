package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/db/sqlc"
)

// PgxExchangeRegistrationRepo backs account.RegistrationLog over the sqlc
// Querier: the local notes of which Exchanges an agent registered at.
type PgxExchangeRegistrationRepo struct {
	q *sqlc.Queries
}

// NewExchangeRegistrationRepo constructs the registration-log repo over the
// given pool.
func NewExchangeRegistrationRepo(pool *pgxpool.Pool) *PgxExchangeRegistrationRepo {
	return &PgxExchangeRegistrationRepo{q: sqlc.New(pool)}
}

// Record notes that subdomain registered at exchange, at. Repeating a note
// refreshes its timestamp rather than adding a second row, so the "refreshed on
// status calls" path needs no read-then-write and no transaction.
//
// The same statement drops this agent's oldest notes past
// account.MaxExchangeRegistrations. Still one statement, so still no
// transaction: see the query for why the row being written is kept by
// construction rather than by being selected.
func (r *PgxExchangeRegistrationRepo) Record(
	ctx context.Context, subdomain, exchange string, at time.Time,
) error {
	err := r.q.RecordExchangeRegistration(ctx, sqlc.RecordExchangeRegistrationParams{
		Subdomain: subdomain,
		Exchange:  exchange,
		// The column is NOT NULL, so Valid is unconditionally true: an invalid
		// Timestamptz would be sent as NULL and refused by the column, which is
		// the right shape for a note whose whole content is when it was written.
		RegisteredAt: pgtype.Timestamptz{Time: at, Valid: true},
		// The cap minus this row, which the query keeps unconditionally. Derived
		// here from the one constant rather than written as a second number.
		KeepOthers: account.MaxExchangeRegistrations - 1,
	})
	if err != nil {
		return mapWriteErr(err, account.ErrUnavailable, "record exchange registration")
	}
	return nil
}

// Forget drops subdomain's note for exchange. Deleting a note that is not there
// is a success: the caller's intent is that no note remain, and it does not.
func (r *PgxExchangeRegistrationRepo) Forget(ctx context.Context, subdomain, exchange string) error {
	err := r.q.ForgetExchangeRegistration(ctx, sqlc.ForgetExchangeRegistrationParams{
		Subdomain: subdomain,
		Exchange:  exchange,
	})
	if err != nil {
		return mapWriteErr(err, account.ErrUnavailable, "forget exchange registration")
	}
	return nil
}

// List returns subdomain's notes, ordered by Exchange domain, bounded by the
// same cap the write path enforces.
//
// An agent with none gets an empty list and no error. Having registered nowhere
// is the state every agent starts in, so it is an answer rather than a miss —
// which is why this does not map to account.ErrNotFound the way a single-row
// read does.
func (r *PgxExchangeRegistrationRepo) List(
	ctx context.Context, subdomain string,
) ([]account.ExchangeRegistration, error) {
	rows, err := r.q.ListExchangeRegistrations(ctx, sqlc.ListExchangeRegistrationsParams{
		Subdomain: subdomain,
		MaxNotes:  account.MaxExchangeRegistrations,
	})
	if err != nil {
		return nil, mapWriteErr(err, account.ErrUnavailable, "list exchange registrations")
	}
	out := make([]account.ExchangeRegistration, 0, len(rows))
	for _, row := range rows {
		out = append(out, account.ExchangeRegistration{
			Exchange:     row.Exchange,
			RegisteredAt: row.RegisteredAt.Time,
		})
	}
	return out, nil
}

// Compile-time assertion that this repo satisfies the port the MCP adapter and
// the domain package declare. Stated here rather than left to the wiring, so a
// method that drifts from the contract fails the build in this file rather than
// at the composition root.
var _ account.RegistrationLog = (*PgxExchangeRegistrationRepo)(nil)

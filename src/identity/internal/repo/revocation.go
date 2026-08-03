package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
)

// PgxRevocationRepo backs the per-subdomain key revocation list over the sqlc
// Querier. Its read side satisfies directory.RevocationReader (the publisher's port);
// its write side, Revoke, is driven by the revocation service. Integration tests
// arrange and assert revocation state through these methods — the same surface
// production uses — never raw SQL.
type PgxRevocationRepo struct {
	q *sqlc.Queries
}

// NewRevocationRepo constructs a revocation repo over the given pool.
func NewRevocationRepo(pool *pgxpool.Pool) *PgxRevocationRepo {
	return &PgxRevocationRepo{q: sqlc.New(pool)}
}

// Revoke appends thumbprint to subdomain's revoked set and advances the subdomain's
// monotonic as_of to a value strictly greater than both its previous value and
// nowEpoch, returning the new as_of. It is a single atomic upsert: concurrent revokes
// of one subdomain serialize on the row and can never share an as_of, which is what
// the consumer's rollback guard depends on. nowEpoch comes from the caller's injected
// clock, not the database.
func (r *PgxRevocationRepo) Revoke(
	ctx context.Context, subdomain, thumbprint string, nowEpoch int64,
) (int64, error) {
	asOf, err := r.q.Revoke(ctx, sqlc.RevokeParams{
		Subdomain:  subdomain,
		NowEpoch:   nowEpoch,
		Thumbprint: thumbprint,
	})
	if err != nil {
		if isUnavailable(err) {
			return 0, directory.ErrRevocationUnavailable
		}
		return 0, fmt.Errorf("revoke %q/%s: %w", subdomain, thumbprint, err)
	}
	return asOf, nil
}

// BySubdomain returns subdomain's current as_of and revoked set, or the empty baseline
// (0, empty) when the subdomain has no revocation row — translating pgx.ErrNoRows at
// the persistence boundary so the serving layer never sees a driver error. Once any
// real revocation lands, as_of is a large monotonic value that always beats that
// baseline, so the two can never be confused on the wire. (The verb matches
// CardReader.BySubdomain — one shape, one name, for reading an agent's doc.)
func (r *PgxRevocationRepo) BySubdomain(ctx context.Context, subdomain string) (int64, []string, error) {
	row, err := r.q.GetRevocation(ctx, subdomain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, []string{}, nil // nothing revoked yet → epoch-dated baseline
		}
		if isUnavailable(err) {
			return 0, nil, directory.ErrRevocationUnavailable
		}
		return 0, nil, fmt.Errorf("get revocation %q: %w", subdomain, err)
	}
	return row.AsOf, row.Revoked, nil
}

var _ directory.RevocationReader = (*PgxRevocationRepo)(nil)

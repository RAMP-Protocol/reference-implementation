// Package repo provides narrow, domain-specific interfaces over the generated
// sqlc Querier for the Identity Service. The serving layer depends on these
// interfaces, not on the fat Querier directly.
package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
)

// CardWriter persists card metadata. Sign-up writes through it, and
// integration tests arrange card state through it rather than raw SQL. The read
// port the handler depends on is directory.CardReader, which PgxCardRepo also
// satisfies — the writer is a separate, narrower surface for the write path.
type CardWriter interface {
	Upsert(ctx context.Context, subdomain string, card directory.Card) (directory.Card, error)
}

// PgxCardRepo backs both CardReader and CardWriter over the sqlc Querier.
type PgxCardRepo struct {
	q *sqlc.Queries
}

// NewCardRepo constructs a card repo over the given pool.
func NewCardRepo(pool *pgxpool.Pool) *PgxCardRepo {
	return &PgxCardRepo{q: sqlc.New(pool)}
}

// BySubdomain returns the card stored for subdomain, or directory.ErrCardNotFound
// when no row exists (translating pgx.ErrNoRows at the persistence boundary so the
// serving layer never sees a driver error).
func (r *PgxCardRepo) BySubdomain(ctx context.Context, subdomain string) (directory.Card, error) {
	row, err := r.q.GetCardBySubdomain(ctx, subdomain)
	if err != nil {
		return directory.Card{}, mapReadErr(err, directory.ErrCardNotFound, directory.ErrCardUnavailable,
			fmt.Sprintf("get card %q", subdomain))
	}
	return toCard(row), nil
}

// Upsert writes card under subdomain, creating or replacing the row, and returns
// the stored card. Contacts is normalized to a non-nil slice so a nil input maps
// to an empty SQL array rather than NULL (the column is NOT NULL).
func (r *PgxCardRepo) Upsert(ctx context.Context, subdomain string, card directory.Card) (directory.Card, error) {
	contacts := card.Contacts
	if contacts == nil {
		contacts = []string{}
	}
	row, err := r.q.UpsertCard(ctx, sqlc.UpsertCardParams{
		Subdomain:  subdomain,
		ClientName: card.ClientName,
		ClientUri:  card.ClientURI,
		Contacts:   contacts,
		Purpose:    card.Purpose,
	})
	if err != nil {
		return directory.Card{}, fmt.Errorf("upsert card %q: %w", subdomain, err)
	}
	return toCard(row), nil
}

// isUnavailable reports whether err is a transient store outage rather than a
// query result — a refused/broken connection, a cancelled/timed-out context, or a
// server-side connection/resource SQLSTATE class (08 connection exception, 53
// insufficient resources, 57 operator intervention). These map to a retryable 503;
// anything else is a genuine 500.
func isUnavailable(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var ce *pgconn.ConnectError
	if errors.As(err, &ce) {
		return true
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && len(pe.Code) >= 2 {
		switch pe.Code[:2] {
		case "08", "53", "57":
			return true
		}
	}
	return false
}

// toCard maps a stored row to the domain card. The created/updated timestamps are
// storage bookkeeping and are not part of the served card.
func toCard(row sqlc.IdentityAgentCard) directory.Card {
	return directory.Card{
		ClientName: row.ClientName,
		ClientURI:  row.ClientUri,
		Contacts:   row.Contacts,
		Purpose:    row.Purpose,
	}
}

// Interface satisfaction checks.
var (
	_ directory.CardReader = (*PgxCardRepo)(nil)
	_ CardWriter           = (*PgxCardRepo)(nil)
)

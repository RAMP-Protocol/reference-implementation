// Package repo provides narrow, domain-specific interfaces over the generated
// sqlc Querier. Handlers and services depend on these interfaces, not on the
// fat Querier directly.
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db/sqlc"
)

// Exchange is the domain representation of a known exchange row.
// Decouples service logic from sqlc-generated types (repository pattern).
type Exchange struct {
	ID                string
	Domain            string
	Endpoint          string
	TrustLevel        string
	Healthy           bool
	SupportedProfiles []string
	Priority          int32
}

// ExchangeRepo is the narrow interface handlers and services depend on.
type ExchangeRepo interface {
	List(ctx context.Context) ([]Exchange, error)
	GetByDomain(ctx context.Context, domain string) (Exchange, error)
	UpsertFromBootstrap(ctx context.Context, m Exchange) (Exchange, error)
	SetHealth(ctx context.Context, exchangeID string, healthy bool) error
}

// ErrNotFound is returned when a row is not present.
var ErrNotFound = errors.New("repo: not found")

// PgxExchangeRepo wraps sqlc.Querier + pool for transactional ops.
type PgxExchangeRepo struct {
	q    *sqlc.Queries
	pool *pgxpool.Pool
}

// NewExchangeRepo constructs an ExchangeRepo backed by the given pool.
func NewExchangeRepo(pool *pgxpool.Pool) *PgxExchangeRepo {
	return &PgxExchangeRepo{q: sqlc.New(pool), pool: pool}
}

// List returns healthy, non-blocked exchanges sorted by priority.
func (r *PgxExchangeRepo) List(ctx context.Context) ([]Exchange, error) {
	rows, err := r.q.ListActiveExchanges(ctx)
	if err != nil {
		return nil, fmt.Errorf("list exchanges: %w", err)
	}
	out := make([]Exchange, 0, len(rows))
	for i := range rows {
		m, convErr := rowToExchange(rows[i])
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, m)
	}
	return out, nil
}

// GetByDomain looks up an exchange by its canonical domain.
func (r *PgxExchangeRepo) GetByDomain(ctx context.Context, domain string) (Exchange, error) {
	const q = `
SELECT exchange_id, domain, endpoint, trust_level, healthy,
       supported_profiles, priority
  FROM broker.exchanges
 WHERE domain = $1
 LIMIT 1
`
	row := r.pool.QueryRow(ctx, q, domain)
	var (
		id       string
		dom      string
		endpoint string
		trust    sqlc.BrokerTrustLevel
		healthy  bool
		profiles []byte
		priority int32
	)
	if err := row.Scan(&id, &dom, &endpoint, &trust, &healthy, &profiles, &priority); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Exchange{}, ErrNotFound
		}
		return Exchange{}, fmt.Errorf("get exchange by domain: %w", err)
	}
	supported, err := decodeProfiles(profiles)
	if err != nil {
		return Exchange{}, err
	}
	return Exchange{
		ID:                id,
		Domain:            dom,
		Endpoint:          endpoint,
		TrustLevel:        string(trust),
		Healthy:           healthy,
		SupportedProfiles: supported,
		Priority:          priority,
	}, nil
}

// UpsertFromBootstrap reconciles a bootstrap entry into the exchanges table.
//
// The endpoint is canonicalized on store (trailing "/" trimmed) so the single
// stored form is what discovery advertises, what the agent signs its
// @target-uri against, and what the relay's SSRF allowlist compares.
// Without this, a trailing-slash endpoint would be admitted by the
// allowlist but the reconstructed double-slash @target-uri would fail-closed in
// sig1 verification, silently breaking such Exchanges over the relay.
func (r *PgxExchangeRepo) UpsertFromBootstrap(ctx context.Context, m Exchange) (Exchange, error) {
	profiles, err := json.Marshal(m.SupportedProfiles)
	if err != nil {
		return Exchange{}, fmt.Errorf("marshal supported_profiles: %w", err)
	}
	row, err := r.q.UpsertExchange(ctx, sqlc.UpsertExchangeParams{
		ExchangeID:        m.ID,
		Domain:            m.Domain,
		Endpoint:          strings.TrimRight(m.Endpoint, "/"),
		TrustLevel:        sqlc.BrokerTrustLevel(m.TrustLevel),
		SupportedProfiles: profiles,
		Priority:          m.Priority,
	})
	if err != nil {
		return Exchange{}, fmt.Errorf("upsert exchange: %w", err)
	}
	return rowToExchange(row)
}

// SetHealth updates the healthy flag on an exchange, used by the refresher.
func (r *PgxExchangeRepo) SetHealth(ctx context.Context, exchangeID string, healthy bool) error {
	const q = `
UPDATE broker.exchanges
   SET healthy = $2,
       last_health_check = NOW(),
       updated_at = NOW()
 WHERE exchange_id = $1
`
	_, err := r.pool.Exec(ctx, q, exchangeID, healthy)
	if err != nil {
		return fmt.Errorf("set health: %w", err)
	}
	return nil
}

func rowToExchange(r sqlc.BrokerExchange) (Exchange, error) {
	supported, err := decodeProfiles(r.SupportedProfiles)
	if err != nil {
		return Exchange{}, err
	}
	return Exchange{
		ID:                r.ExchangeID,
		Domain:            r.Domain,
		Endpoint:          r.Endpoint,
		TrustLevel:        string(r.TrustLevel),
		Healthy:           r.Healthy,
		SupportedProfiles: supported,
		Priority:          r.Priority,
	}, nil
}

func decodeProfiles(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode supported_profiles: %w", err)
	}
	return out, nil
}

// Silence pgtype unused-import lint in stricter builds; retained for possible
// future fields (timestamps).
var _ pgtype.Text

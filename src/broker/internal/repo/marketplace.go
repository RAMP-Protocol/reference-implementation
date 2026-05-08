// Package repo provides narrow, domain-specific interfaces over the generated
// sqlc Querier. Handlers and services depend on these interfaces, not on the
// fat Querier directly.
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db/sqlc"
)

// Marketplace is the domain representation of a known marketplace row.
// Decouples service logic from sqlc-generated types (repository pattern).
type Marketplace struct {
	ID                string
	Domain            string
	Endpoint          string
	TrustLevel        string
	Healthy           bool
	SupportedProfiles []string
	Priority          int32
}

// MarketplaceRepo is the narrow interface handlers and services depend on.
type MarketplaceRepo interface {
	List(ctx context.Context) ([]Marketplace, error)
	GetByDomain(ctx context.Context, domain string) (Marketplace, error)
	UpsertFromBootstrap(ctx context.Context, m Marketplace) (Marketplace, error)
	SetHealth(ctx context.Context, marketplaceID string, healthy bool) error
}

// ErrNotFound is returned when a row is not present.
var ErrNotFound = errors.New("repo: not found")

// PgxMarketplaceRepo wraps sqlc.Querier + pool for transactional ops.
type PgxMarketplaceRepo struct {
	q    *sqlc.Queries
	pool *pgxpool.Pool
}

// NewMarketplaceRepo constructs a MarketplaceRepo backed by the given pool.
func NewMarketplaceRepo(pool *pgxpool.Pool) *PgxMarketplaceRepo {
	return &PgxMarketplaceRepo{q: sqlc.New(pool), pool: pool}
}

// List returns healthy, non-blocked marketplaces sorted by priority.
func (r *PgxMarketplaceRepo) List(ctx context.Context) ([]Marketplace, error) {
	rows, err := r.q.ListActiveMarketplaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("list marketplaces: %w", err)
	}
	out := make([]Marketplace, 0, len(rows))
	for i := range rows {
		m, convErr := rowToMarketplace(rows[i])
		if convErr != nil {
			return nil, convErr
		}
		out = append(out, m)
	}
	return out, nil
}

// GetByDomain looks up a marketplace by its canonical domain.
func (r *PgxMarketplaceRepo) GetByDomain(ctx context.Context, domain string) (Marketplace, error) {
	const q = `
SELECT marketplace_id, domain, endpoint, trust_level, healthy,
       supported_profiles, priority
  FROM broker.marketplaces
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
			return Marketplace{}, ErrNotFound
		}
		return Marketplace{}, fmt.Errorf("get marketplace by domain: %w", err)
	}
	supported, err := decodeProfiles(profiles)
	if err != nil {
		return Marketplace{}, err
	}
	return Marketplace{
		ID:                id,
		Domain:            dom,
		Endpoint:          endpoint,
		TrustLevel:        string(trust),
		Healthy:           healthy,
		SupportedProfiles: supported,
		Priority:          priority,
	}, nil
}

// UpsertFromBootstrap reconciles a bootstrap entry into the marketplaces table.
func (r *PgxMarketplaceRepo) UpsertFromBootstrap(ctx context.Context, m Marketplace) (Marketplace, error) {
	profiles, err := json.Marshal(m.SupportedProfiles)
	if err != nil {
		return Marketplace{}, fmt.Errorf("marshal supported_profiles: %w", err)
	}
	row, err := r.q.UpsertMarketplace(ctx, sqlc.UpsertMarketplaceParams{
		MarketplaceID:     m.ID,
		Domain:            m.Domain,
		Endpoint:          m.Endpoint,
		TrustLevel:        sqlc.BrokerTrustLevel(m.TrustLevel),
		SupportedProfiles: profiles,
		Priority:          m.Priority,
	})
	if err != nil {
		return Marketplace{}, fmt.Errorf("upsert marketplace: %w", err)
	}
	return rowToMarketplace(row)
}

// SetHealth updates the healthy flag on a marketplace, used by the refresher.
func (r *PgxMarketplaceRepo) SetHealth(ctx context.Context, marketplaceID string, healthy bool) error {
	const q = `
UPDATE broker.marketplaces
   SET healthy = $2,
       last_health_check = NOW(),
       updated_at = NOW()
 WHERE marketplace_id = $1
`
	_, err := r.pool.Exec(ctx, q, marketplaceID, healthy)
	if err != nil {
		return fmt.Errorf("set health: %w", err)
	}
	return nil
}

func rowToMarketplace(r sqlc.BrokerMarketplace) (Marketplace, error) {
	supported, err := decodeProfiles(r.SupportedProfiles)
	if err != nil {
		return Marketplace{}, err
	}
	return Marketplace{
		ID:                r.MarketplaceID,
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

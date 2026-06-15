package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// CatalogEntry is the domain view of a catalog row.
type CatalogEntry struct {
	ResourceID     string
	TenantID       string
	URI            string
	URIPrefix      string
	PricingJSON    []byte
	LicensingJSON  []byte
	DeliveryMethod string
}

// CatalogRepo is the narrow contract CatalogService needs.
type CatalogRepo interface {
	Upsert(ctx context.Context, e CatalogEntry) (CatalogEntry, error)
	// UpsertTx runs the same upsert inside an open transaction so a batch of
	// entries commits atomically (Arch rule 7).
	UpsertTx(ctx context.Context, tx pgx.Tx, e CatalogEntry) (CatalogEntry, error)
	ListAll(ctx context.Context) ([]CatalogEntry, error)
	ByID(ctx context.Context, resourceID string) (CatalogEntry, error)
}

// ErrCatalogNotFound is returned when a catalog lookup has no match.
var ErrCatalogNotFound = errors.New("repo: catalog entry not found")

// NewCatalogRepo composes a CatalogRepo over a sqlc.Querier.
func NewCatalogRepo(q sqlc.Querier) CatalogRepo { return &catalogRepo{q: q} }

type catalogRepo struct{ q sqlc.Querier }

func (r *catalogRepo) Upsert(ctx context.Context, e CatalogEntry) (CatalogEntry, error) {
	return upsertCatalog(ctx, r.q, e)
}

func (r *catalogRepo) UpsertTx(ctx context.Context, tx pgx.Tx, e CatalogEntry) (CatalogEntry, error) {
	return upsertCatalog(ctx, sqlc.New(tx), e)
}

// upsertCatalog performs the upsert against any sqlc.Querier — the pool-bound
// querier (Upsert) or a tx-bound one created via sqlc.New(tx) (UpsertTx).
func upsertCatalog(ctx context.Context, q sqlc.Querier, e CatalogEntry) (CatalogEntry, error) {
	row, err := q.UpsertCatalogEntry(ctx, sqlc.UpsertCatalogEntryParams{
		ResourceID:     e.ResourceID,
		TenantID:       e.TenantID,
		Uri:            e.URI,
		UriPrefix:      e.URIPrefix,
		Pricing:        e.PricingJSON,
		LicensingRules: jsonOrEmpty(e.LicensingJSON),
		DeliveryMethod: sqlc.RampDeliveryMethod(e.DeliveryMethod),
	})
	if err != nil {
		return CatalogEntry{}, fmt.Errorf("upsert catalog entry: %w", err)
	}
	return catalogFromRow(row), nil
}

func (r *catalogRepo) ListAll(ctx context.Context) ([]CatalogEntry, error) {
	rows, err := r.q.ListAllCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("list all catalog: %w", err)
	}
	out := make([]CatalogEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, catalogFromRow(row))
	}
	return out, nil
}

func (r *catalogRepo) ByID(ctx context.Context, resourceID string) (CatalogEntry, error) {
	row, err := r.q.GetCatalogEntry(ctx, resourceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CatalogEntry{}, ErrCatalogNotFound
		}
		return CatalogEntry{}, fmt.Errorf("get catalog entry: %w", err)
	}
	return catalogFromRow(row), nil
}

func catalogFromRow(row sqlc.RampCatalog) CatalogEntry {
	return CatalogEntry{
		ResourceID:     row.ResourceID,
		TenantID:       row.TenantID,
		URI:            row.Uri,
		URIPrefix:      row.UriPrefix,
		PricingJSON:    row.Pricing,
		LicensingJSON:  row.LicensingRules,
		DeliveryMethod: string(row.DeliveryMethod),
	}
}

func jsonOrEmpty(b []byte) []byte {
	if len(b) == 0 {
		return []byte(`{}`)
	}
	return b
}

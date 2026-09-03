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
	TermsJSON      []byte
	DeliveryMethod string
	// MetadataJSON is the serialized resource extension metadata,
	// nullable: nil round-trips to a NULL column and back to nil.
	MetadataJSON []byte
	// ResourceOwnerID is the owner-attested payee the entry's revenue settles to,
	// distinct from TenantID (the operational slot). Sourced server-side from the
	// owner manifest at push; the push gate guarantees it is non-empty.
	ResourceOwnerID string
	// Title is the resource's human-readable label, taken from the pushed
	// ResourceEntry.title and projected onto Offer.title before the offer is
	// signed. Nullable: nil round-trips to a NULL column and back to nil, which
	// is how "the push carried no title" stays distinct from an empty string.
	// It is stored in its own column rather than in MetadataJSON because that
	// document projects only the extension-metadata fields.
	Title *string
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

// ErrCatalogURIImmutable is returned when an upsert would change the URI of an
// existing resource_id. The catalog URI is immutable per resource: a signed
// offer binds at execute via its Identity.canonical_url, so a URI move would
// free the old URI for another resource and let a still-valid offer rebind to
// it. The service precheck rejects the move per-entry; this error is the
// race-safe database backstop (the upsert's DO UPDATE is guarded on an
// unchanged uri and returns no row when the guard fails).
var ErrCatalogURIImmutable = errors.New("repo: catalog uri is immutable for an existing resource_id")

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
		ResourceID:      e.ResourceID,
		TenantID:        e.TenantID,
		Uri:             e.URI,
		UriPrefix:       e.URIPrefix,
		Pricing:         e.PricingJSON,
		Terms:           termsOrEmpty(e.TermsJSON),
		DeliveryMethod:  sqlc.RampDeliveryMethod(e.DeliveryMethod),
		Metadata:        e.MetadataJSON,
		ResourceOwnerID: e.ResourceOwnerID,
		Title:           pgTextPtr(e.Title),
	})
	if err != nil {
		// The guarded DO UPDATE (WHERE catalog.uri = EXCLUDED.uri) is the only
		// way this INSERT ... RETURNING yields no row: the resource exists and
		// the push tried to move its URI.
		if errors.Is(err, pgx.ErrNoRows) {
			return CatalogEntry{}, ErrCatalogURIImmutable
		}
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
		ResourceID:      row.ResourceID,
		TenantID:        row.TenantID,
		URI:             row.Uri,
		URIPrefix:       row.UriPrefix,
		PricingJSON:     row.Pricing,
		TermsJSON:       row.Terms,
		DeliveryMethod:  string(row.DeliveryMethod),
		MetadataJSON:    row.Metadata,
		ResourceOwnerID: row.ResourceOwnerID,
		Title:           textFromPG(row.Title),
	}
}

// termsOrEmpty defaults an absent terms payload to an empty JSON array so the
// NOT NULL terms JSONB column (DEFAULT '[]') always receives a well-formed
// array, matching the repeated LicenseTerm shape the publisher pushes.
func termsOrEmpty(b []byte) []byte {
	if len(b) == 0 {
		return []byte(`[]`)
	}
	return b
}

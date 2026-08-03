//go:build integration

package service

import (
	"context"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	protobuf "google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service/servicetest"
)

// TestCatalogMetadataPersists is the Tier-2 repo round-trip deferred from the
// sqlc/repo task: it proves the metadata JSONB written by the
// production write projection (entryFromProto) survives a real Upsert and ByID
// read and decodes back to the same metadata. The full public-RPC round-trip
// (push -> discover) is a separate e2e; this asserts persistence through the
// production repository interface (no raw SQL), the documented surface-hierarchy
// fallback while no public metadata read surface exists yet (Doctrine pt 9).
func TestCatalogMetadataPersists(t *testing.T) {
	ctx := context.Background()
	pool := servicetest.AcquireTestDB(t, ctx)

	// pt9 documented corner: no public tenant-provisioning RPC exists yet, so the
	// tenant prerequisite is seeded via the sqlc InsertTenant query (the same
	// surface sibling Exchange tests use), not a raw SQL string.
	if _, err := sqlc.New(pool).InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID: "t1", Domain: "publisher.example", HmacSecretRef: "h", Ed25519KeyRef: "k",
		ReportingPolicy: []byte(`{}`), SigningScheme: sqlc.RampSigningSchemeED25519,
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	realRepo := repo.NewCatalogRepo(sqlc.New(pool))

	// Metadata-bearing entry goes through the production write projection.
	withMeta, err := entryFromProto("t1", metadataEntry(t))
	if err != nil {
		t.Fatalf("entryFromProto (with metadata): %v", err)
	}
	if _, err := realRepo.Upsert(ctx, withMeta); err != nil {
		t.Fatalf("upsert with metadata: %v", err)
	}
	// Legacy entry without metadata must persist a NULL column (nil MetadataJSON).
	noMeta, err := entryFromProto("t1", &rampv1.ResourceEntry{Domain: "publisher.example", Path: "/article/legacy"})
	if err != nil {
		t.Fatalf("entryFromProto (no metadata): %v", err)
	}
	if _, err := realRepo.Upsert(ctx, noMeta); err != nil {
		t.Fatalf("upsert without metadata: %v", err)
	}

	assertMetadataRoundTrip(t, ctx, realRepo, withMeta.ResourceID, metadataEntry(t))
	assertNoMetadata(t, ctx, realRepo, noMeta.ResourceID)
}

// assertMetadataRoundTrip reads the row back through the repo and asserts the
// stored metadata decodes to the same metadata-only projection.
func assertMetadataRoundTrip(t *testing.T, ctx context.Context, r repo.CatalogRepo, id string, src *rampv1.ResourceEntry) {
	t.Helper()
	got, err := r.ByID(ctx, id)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.MetadataJSON == nil {
		t.Fatal("metadata column is NULL for a metadata-bearing entry")
	}
	decoded, err := unmarshalResourceMetadata(got.MetadataJSON)
	if err != nil {
		t.Fatalf("decode stored metadata: %v", err)
	}
	want, err := marshalResourceMetadata(src)
	if err != nil {
		t.Fatalf("marshal source metadata: %v", err)
	}
	wantEntry, err := unmarshalResourceMetadata(want)
	if err != nil {
		t.Fatalf("decode source metadata: %v", err)
	}
	if !protobuf.Equal(decoded, wantEntry) {
		t.Errorf("persisted metadata mismatch:\n got=%v\nwant=%v", decoded, wantEntry)
	}
}

// assertNoMetadata asserts a legacy row persisted a NULL metadata column.
func assertNoMetadata(t *testing.T, ctx context.Context, r repo.CatalogRepo, id string) {
	t.Helper()
	got, err := r.ByID(ctx, id)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.MetadataJSON != nil {
		t.Errorf("expected NULL metadata for a legacy entry, got %s", got.MetadataJSON)
	}
}

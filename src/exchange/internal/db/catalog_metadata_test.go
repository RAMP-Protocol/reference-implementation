//go:build integration

package db_test

import (
	"context"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
)

// TestCatalogMetadataMigration verifies the additive 000014 migration that adds
// the nullable `metadata` JSONB column to ramp.catalog:
//   - up (to head) adds the column.
//   - down (Migrate(13)) drops it — the exact inverse.
//
// Migrate(13) reverses everything above version 13 (i.e. the 000014 ADD),
// leaving the column gone; navigating to an explicit version rather than
// Steps(-1) keeps the test stable as later migrations are added above 000014.
// hasColumn and migrator are shared with catalog_terms_test.go (same package).
func TestCatalogMetadataMigration(t *testing.T) {
	ctx := context.Background()
	// Up to head — metadata added (000014).
	dsn := sharedb.AcquireTestDSN(t, ctx, sharedPG)
	if !hasColumn(t, ctx, dsn, "metadata") {
		t.Fatal("after up: ramp.catalog is missing the metadata column")
	}

	m := schemaProbe.Migrator(t, dsn)

	// Migrate(13) reverses the 000014 ADD: the metadata column is removed.
	if err := m.Migrate(13); err != nil {
		t.Fatalf("migrate to version 13 (reverse 000014): %v", err)
	}
	if hasColumn(t, ctx, dsn, "metadata") {
		t.Fatal("after down 000014: ramp.catalog still has the metadata column")
	}
}

//go:build integration

package db_test

import (
	"context"
	"testing"
)

// TestCatalogResourceOwnerMigration verifies the additive 000018 migration that
// adds the resource_owner_id column to ramp.catalog:
//   - up (to head) adds the column.
//   - down (Migrate(17)) drops it — the exact inverse.
//
// Migrate(17) reverses everything above version 17 (i.e. the 000018 ADD), leaving
// the column gone; navigating to an explicit version rather than Steps(-1) keeps the
// test stable as later migrations are added above 000018. hasColumn and migrator are
// shared with catalog_metadata_test.go / catalog_terms_test.go (same package).
func TestCatalogResourceOwnerMigration(t *testing.T) {
	ctx := context.Background()
	// Up to head — resource_owner_id added (000018).
	dsn := migratedDSN(t, ctx)
	if !hasColumn(t, ctx, dsn, "resource_owner_id") {
		t.Fatal("after up: ramp.catalog is missing the resource_owner_id column")
	}

	m := migrator(t, dsn)
	defer m.Close()

	// Migrate(17) reverses the 000018 ADD: the resource_owner_id column is removed.
	if err := m.Migrate(17); err != nil {
		t.Fatalf("migrate to version 17 (reverse 000018): %v", err)
	}
	if hasColumn(t, ctx, dsn, "resource_owner_id") {
		t.Fatal("after down 000018: ramp.catalog still has the resource_owner_id column")
	}
}

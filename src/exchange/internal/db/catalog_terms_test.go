//go:build integration

package db_test

import (
	"context"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
)

// hasColumn is this package's only wrapper over the shared probe, and it earns the
// place by narrowing: it fixes the table to catalog, which the shared probe does
// not, and most questions here are about that one table. Every other question goes
// through schemaProbe directly — main_test.go names this package's schema and
// migration source once — so a wrapper here means "narrowed for this package" and
// nothing else.
func hasColumn(tb testing.TB, ctx context.Context, dsn, col string) bool {
	tb.Helper()
	return schemaProbe.HasColumn(tb, ctx, dsn, "catalog", col)
}

// TestCatalogTermsMigration verifies the EXPAND/CONTRACT pair that moves
// ramp.catalog off the legacy licensing_rules column onto terms:
//   - 000010 (EXPAND) adds terms.
//   - 000011 (CONTRACT) drops licensing_rules.
//
// At head both invariants hold (terms present, licensing_rules gone). Stepping
// down reverses them in order: -1 restores licensing_rules (still has terms),
// -1 again removes terms — proving each migration's down is the exact inverse
// of its up.
func TestCatalogTermsMigration(t *testing.T) {
	ctx := context.Background()
	// Up to head — terms added (000010), licensing_rules dropped (000011).
	dsn := sharedb.AcquireTestDSN(t, ctx, sharedPG)
	if !hasColumn(t, ctx, dsn, "terms") {
		t.Fatal("after up: ramp.catalog is missing the terms column")
	}
	if hasColumn(t, ctx, dsn, "licensing_rules") {
		t.Fatal("after up: ramp.catalog still has the licensing_rules column")
	}

	m := schemaProbe.Migrator(t, dsn)

	// Navigate to explicit schema versions instead of counting Steps(-1) from a
	// moving head: every migration added above the EXPAND/CONTRACT pair (000012
	// catalog_uri UNIQUE, 000013 denial_reason enum add, and any future one)
	// would otherwise shift the step math and break this test. Migrate(10)
	// reverses everything above version 10 — including the 000011 CONTRACT —
	// leaving the pre-CONTRACT state: terms present (000010 up) and
	// licensing_rules restored (000011 down).
	if err := m.Migrate(10); err != nil {
		t.Fatalf("migrate to version 10 (reverse 000011 CONTRACT): %v", err)
	}
	if !hasColumn(t, ctx, dsn, "licensing_rules") {
		t.Fatal("after down 000011: licensing_rules was not restored")
	}
	if !hasColumn(t, ctx, dsn, "terms") {
		t.Fatal("after down 000011: terms column disappeared prematurely")
	}

	// Migrate(9) reverses the 000010 EXPAND: the terms column is removed.
	if err := m.Migrate(9); err != nil {
		t.Fatalf("migrate to version 9 (reverse 000010 EXPAND): %v", err)
	}
	if hasColumn(t, ctx, dsn, "terms") {
		t.Fatal("after down 000010: ramp.catalog still has the terms column")
	}
}

//go:build integration

package db_test

import (
	"context"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
)

// TestTenantDefaultCreditMigration verifies the default-agent-credit schema
// change: 000026 adds ramp.tenants.default_agent_credit. At head the column
// holds; stepping down to the explicit prior version (not Steps(-1), so later
// migrations stacking on top do not shift the math) removes it — proving the
// down is the exact inverse of the up.
func TestTenantDefaultCreditMigration(t *testing.T) {
	ctx := context.Background()
	dsn := sharedb.AcquireTestDSN(t, ctx, sharedPG)
	if !schemaProbe.HasColumn(t, ctx, dsn, "tenants", "default_agent_credit") {
		t.Fatal("after up: ramp.tenants is missing the default_agent_credit column")
	}

	m := schemaProbe.Migrator(t, dsn)

	// Migrate(25) reverses the 000026 ADD COLUMN.
	if err := m.Migrate(25); err != nil {
		t.Fatalf("migrate to version 25 (reverse 000026): %v", err)
	}
	if schemaProbe.HasColumn(t, ctx, dsn, "tenants", "default_agent_credit") {
		t.Fatal("after down 000026: ramp.tenants still has the default_agent_credit column")
	}
}

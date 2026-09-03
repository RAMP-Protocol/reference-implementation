//go:build integration

package db_test

import (
	"context"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
)

// TestTenantFeeRateMigration verifies the commission-rate schema pair:
//   - 000019 adds ramp.tenants.fee_rate_bps + fee_rate_notes.
//   - 000020 adds the ramp.tenant_resource_owner_fee override table.
//
// At head both hold. Stepping down to explicit versions (not Steps(-1), so later
// migrations stacking on top do not shift the math) reverses them in order:
// Migrate(19) drops the override table while the tenant columns remain; Migrate(18)
// then drops the tenant columns — proving each down is the exact inverse of its up.
func TestTenantFeeRateMigration(t *testing.T) {
	ctx := context.Background()
	dsn := sharedb.AcquireTestDSN(t, ctx, sharedPG)
	if !schemaProbe.HasColumn(t, ctx, dsn, "tenants", "fee_rate_bps") {
		t.Fatal("after up: ramp.tenants is missing the fee_rate_bps column")
	}
	if !schemaProbe.HasColumn(t, ctx, dsn, "tenants", "fee_rate_notes") {
		t.Fatal("after up: ramp.tenants is missing the fee_rate_notes column")
	}
	if !schemaProbe.HasTable(t, ctx, dsn, "tenant_resource_owner_fee") {
		t.Fatal("after up: ramp.tenant_resource_owner_fee table is missing")
	}

	m := schemaProbe.Migrator(t, dsn)

	// Migrate(19) reverses the 000020 CREATE TABLE; the 000019 tenant columns stay.
	if err := m.Migrate(19); err != nil {
		t.Fatalf("migrate to version 19 (reverse 000020): %v", err)
	}
	if schemaProbe.HasTable(t, ctx, dsn, "tenant_resource_owner_fee") {
		t.Fatal("after down 000020: ramp.tenant_resource_owner_fee table still exists")
	}
	if !schemaProbe.HasColumn(t, ctx, dsn, "tenants", "fee_rate_bps") {
		t.Fatal("after down 000020: fee_rate_bps disappeared prematurely")
	}

	// Migrate(18) reverses the 000019 ADD COLUMN: both tenant fee columns removed.
	if err := m.Migrate(18); err != nil {
		t.Fatalf("migrate to version 18 (reverse 000019): %v", err)
	}
	if schemaProbe.HasColumn(t, ctx, dsn, "tenants", "fee_rate_bps") {
		t.Fatal("after down 000019: ramp.tenants still has the fee_rate_bps column")
	}
	if schemaProbe.HasColumn(t, ctx, dsn, "tenants", "fee_rate_notes") {
		t.Fatal("after down 000019: ramp.tenants still has the fee_rate_notes column")
	}
}

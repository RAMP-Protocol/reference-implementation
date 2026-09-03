//go:build integration

package db_test

import (
	"context"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// TestTenantHMACSecretRefMigration verifies the 000031 DROP both ways:
//   - at head ramp.tenants no longer carries hmac_secret_ref.
//   - stepping down to version 30 restores it as 000001 declared it, TEXT NOT
//     NULL with no default, appended after the last column rather than in its
//     original position, and with every existing row backfilled.
//
// The down file adds the column with a temporary default so existing rows
// satisfy NOT NULL, then drops that default. Both halves are pinned. The step
// down runs against a populated table, because on an empty one Postgres accepts
// ADD COLUMN ... NOT NULL without any default and a down file missing the
// backfill would pass; and the absence of a default is asserted, because a down
// file that kept it would restore a schema that differs from the one it claims
// to restore while a name-only check still passes.
//
// Migrate(30) is an explicit version rather than Steps(-1) so migrations stacked
// above 000031 later do not shift the math.
func TestTenantHMACSecretRefMigration(t *testing.T) {
	ctx := context.Background()
	dsn := sharedb.AcquireTestDSN(t, ctx, sharedPG)

	if schemaProbe.HasColumn(t, ctx, dsn, "tenants", "hmac_secret_ref") {
		t.Fatal("after up: ramp.tenants still has the hmac_secret_ref column")
	}

	// Seed one tenant so the down migration's NOT NULL backfill is exercised.
	// The row is arranged through the sqlc layer because there is no tenant
	// creation RPC and TenantWriteRepo has no create surface. The pool is closed
	// before the schema is stepped so the migrator holds the only session.
	const tenantID = "t_hmac_secret_ref_down"
	pool := sharedb.OpenForTest(t, ctx, dsn)
	if _, err := sqlc.New(pool).InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          tenantID + ".example",
		Ed25519KeyRef:   "secret://ed25519/" + tenantID,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
	}); err != nil {
		t.Fatalf("InsertTenant: %v", err)
	}
	pool.Close()

	m := schemaProbe.Migrator(t, dsn)

	if err := m.Migrate(30); err != nil {
		t.Fatalf("migrate to version 30 (reverse 000031) with one tenant row: %v", err)
	}
	if !schemaProbe.HasColumn(t, ctx, dsn, "tenants", "hmac_secret_ref") {
		t.Fatal("after down 000031: ramp.tenants is missing the hmac_secret_ref column")
	}
	if !schemaProbe.HasColumnType(t, ctx, dsn, "tenants", "hmac_secret_ref", "text") {
		t.Error("after down 000031: hmac_secret_ref is not TEXT")
	}
	if !schemaProbe.HasColumnNotNull(t, ctx, dsn, "tenants", "hmac_secret_ref") {
		t.Error("after down 000031: hmac_secret_ref is nullable")
	}
	// No probe helper asserts the absence of a default, and that is the property
	// the down file's second statement exists to produce.
	if !schemaProbe.Exists(t, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			 WHERE table_schema  = 'ramp'
			   AND table_name    = 'tenants'
			   AND column_name   = 'hmac_secret_ref'
			   AND column_default IS NULL
		)`) {
		t.Error("after down 000031: hmac_secret_ref kept the temporary default")
	}
	// POSITIONS. The down file says the column comes back appended, after
	// default_agent_credit, and that this is cosmetic. Pin the observation so the
	// comment and the schema cannot drift apart.
	if !schemaProbe.ColumnComesAfter(t, ctx, dsn, "tenants", "hmac_secret_ref", "default_agent_credit") {
		t.Error("after down 000031: hmac_secret_ref did not come back appended after default_agent_credit")
	}

	// The seeded row survived the backfill. Head's generated query names its
	// columns, none of which is hmac_secret_ref, so it reads the widened table.
	after := sharedb.OpenForTest(t, ctx, dsn)
	got, err := sqlc.New(after).GetTenantByID(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantByID after down 000031: %v", err)
	}
	if got.TenantID != tenantID {
		t.Errorf("after down 000031: tenant row: got %q want %q", got.TenantID, tenantID)
	}
}

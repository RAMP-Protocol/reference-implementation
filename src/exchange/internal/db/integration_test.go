//go:build integration

package db_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// TestExchangeMigrationsSmoke round-trips a tenant through the sqlc layer on
// the migrated-to-head schema (TestMain applies the migrations once for the
// whole package; a migration failure fails the suite before any test runs).
func TestExchangeMigrationsSmoke(t *testing.T) {
	ctx := context.Background()
	pool := sharedb.AcquireTestDB(t, ctx, sharedPG)

	q := sqlc.New(pool)
	tenantID := "t_" + uuid.NewString()

	tenant, err := q.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          tenantID + ".example",
		Ed25519KeyRef:   "secret://ed25519/" + tenantID,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
	})
	if err != nil {
		t.Fatalf("InsertTenant: %v", err)
	}
	if tenant.TenantID != tenantID {
		t.Errorf("tenant_id roundtrip: got %q want %q", tenant.TenantID, tenantID)
	}

	got, err := q.GetTenantByDomain(ctx, tenant.Domain)
	if err != nil {
		t.Fatalf("GetTenantByDomain: %v", err)
	}
	if got.TenantID != tenantID {
		t.Errorf("round-trip tenant_id: got %q want %q", got.TenantID, tenantID)
	}
}

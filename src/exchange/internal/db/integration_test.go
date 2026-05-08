//go:build integration

package db_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

func TestExchangeMigrationsSmoke(t *testing.T) {
	ctx := context.Background()
	dsn := sharedb.StartPostgres(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	pool, err := sharedb.Setup(ctx, sharedb.SetupOptions{
		DSN:             dsn,
		Migrations:      exchangedb.Migrations,
		MigrationsDir:   exchangedb.MigrationsDir,
		MigrationsTable: exchangedb.MigrationsTable,
	}, logger)
	if err != nil {
		t.Fatalf("db setup: %v", err)
	}
	t.Cleanup(pool.Close)

	q := sqlc.New(pool)
	tenantID := "t_" + uuid.NewString()

	tenant, err := q.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          tenantID + ".example",
		HmacSecretRef:   "secret://hmac/" + tenantID,
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

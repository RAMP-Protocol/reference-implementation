//go:build integration

package sor_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the database/sql "pgx" driver used by testcontainers Snapshot/Restore

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	sordb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor/db"
)

// sharedPG is the package's single Postgres container, migrated once with the
// SoR's own migration sequence by TestMain and reset to baseline between tests.
// Written once before m.Run and read-only thereafter, so the serial integration
// tests need no synchronization.
var sharedPG *sharedb.SharedPostgres

// TestMain brings up one shared migrated Postgres for the whole package. The
// os.Exit is delegated to RunIntegrationMain so the container-terminate defer
// runs — os.Exit would skip it.
func TestMain(m *testing.M) {
	os.Exit(testutil.RunIntegrationMain(
		m, sordb.Migrations, sordb.MigrationsDir, sordb.MigrationsTable,
		func(pg *sharedb.SharedPostgres) { sharedPG = pg },
	))
}

// acquireTestDB resets the shared Postgres to its migrated baseline and returns
// a fresh pool. Every integration test in this package obtains its database
// through this helper, exactly once per test. See db.AcquireTestDB for the
// once-per-test and serial-execution contract.
func acquireTestDB(tb testing.TB, ctx context.Context) *pgxpool.Pool {
	tb.Helper()
	return sharedb.AcquireTestDB(tb, ctx, sharedPG)
}

//go:build integration

package repo_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the database/sql "pgx" driver used by testcontainers Snapshot/Restore

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	identitydb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/db"
)

// sharedPG is the package's single Postgres container, migrated once by TestMain
// and reset to its migrated baseline between tests. Written once before m.Run and
// read-only thereafter, so the serial integration tests need no synchronization.
var sharedPG *sharedb.SharedPostgres

func TestMain(m *testing.M) {
	os.Exit(testutil.RunIntegrationMain(
		m, identitydb.Migrations, identitydb.MigrationsDir, identitydb.MigrationsTable,
		func(pg *sharedb.SharedPostgres) { sharedPG = pg },
	))
}

// acquireTestDB resets the shared Postgres to its migrated baseline and returns a
// fresh pool, once per test (see db.AcquireTestDB for the serial-execution contract).
func acquireTestDB(tb testing.TB, ctx context.Context) *pgxpool.Pool {
	tb.Helper()
	return sharedb.AcquireTestDB(tb, ctx, sharedPG)
}

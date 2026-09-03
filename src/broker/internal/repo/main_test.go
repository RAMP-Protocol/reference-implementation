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
	brokerdb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db"
)

// sharedPG holds the package's single migrated Postgres, reset per test
// (Testing Doctrine §11). TestMain writes it once before m.Run; the serial
// integration tests only read it.
var sharedPG *sharedb.SharedPostgres

func TestMain(m *testing.M) {
	os.Exit(testutil.RunIntegrationMain(
		m, brokerdb.Migrations, brokerdb.MigrationsDir, brokerdb.MigrationsTable,
		func(pg *sharedb.SharedPostgres) { sharedPG = pg },
	))
}

// newTestPool resets the shared Postgres to its migrated baseline and returns a
// fresh pool. Called once per test; the suite runs serially per the
// db.AcquireTestDB contract.
func newTestPool(tb testing.TB, ctx context.Context) *pgxpool.Pool {
	tb.Helper()
	return sharedb.AcquireTestDB(tb, ctx, sharedPG)
}

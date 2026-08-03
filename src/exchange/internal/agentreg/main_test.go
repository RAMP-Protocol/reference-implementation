//go:build integration

package agentreg_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the database/sql "pgx" driver used by testcontainers Snapshot/Restore

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
)

// sharedPG holds the package's single migrated Postgres, reset per test. TestMain
// writes it once before m.Run; the serial integration tests only read it.
var sharedPG *sharedb.SharedPostgres

func TestMain(m *testing.M) {
	os.Exit(testutil.RunIntegrationMain(
		m, exchangedb.Migrations, exchangedb.MigrationsDir, exchangedb.MigrationsTable,
		func(pg *sharedb.SharedPostgres) { sharedPG = pg },
	))
}

// acquireTestDB resets the shared Postgres to its migrated baseline and returns a
// fresh pool; newTestQueries calls it once per test. See db.AcquireTestDB for the
// once-per-test and serial-execution contract.
func acquireTestDB(tb testing.TB, ctx context.Context) *pgxpool.Pool {
	tb.Helper()
	return sharedb.AcquireTestDB(tb, ctx, sharedPG)
}

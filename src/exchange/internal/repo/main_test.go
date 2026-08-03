//go:build integration

package repo_test

import (
	"context"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the database/sql "pgx" driver used by testcontainers Snapshot/Restore

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// sharedPG holds the package's single migrated Postgres, reset per test
// (Testing Doctrine §11). TestMain writes it once before m.Run; the serial
// integration tests only read it.
var sharedPG *sharedb.SharedPostgres

func TestMain(m *testing.M) {
	os.Exit(testutil.RunIntegrationMain(
		m, exchangedb.Migrations, exchangedb.MigrationsDir, exchangedb.MigrationsTable,
		func(pg *sharedb.SharedPostgres) { sharedPG = pg },
	))
}

// newTestQueries resets the shared Postgres to its migrated baseline and
// returns a querier over a fresh pool. Called once per test; the suite runs
// serially per the db.AcquireTestDB contract.
func newTestQueries(tb testing.TB, ctx context.Context) sqlc.Querier {
	tb.Helper()
	return sqlc.New(sharedb.AcquireTestDB(tb, ctx, sharedPG))
}

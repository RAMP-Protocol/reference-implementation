//go:build integration

package db_test

import (
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the database/sql "pgx" driver used by testcontainers Snapshot/Restore

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
)

// sharedPG is the package's single Postgres container, migrated to head and
// snapshotted once by TestMain, then reset to that baseline at the start of
// every test (via AcquireTestDSN or AcquireTestDB). Written once before m.Run and
// read-only thereafter; the serial integration tests need no synchronization.
var sharedPG *sharedb.SharedPostgres

// schemaProbe answers the structural questions the migration tests ask — does
// ramp.<table> have this column, does this table exist — and builds the
// golang-migrate handle they step down and back up. It names the Exchange's
// schema and migration source once for the package.
var schemaProbe = sharedb.SchemaProbe{
	Schema:     "ramp",
	Migrations: exchangedb.Migrations,
	Dir:        exchangedb.MigrationsDir,
	Table:      exchangedb.MigrationsTable,
}

// TestMain brings up one Postgres container for the whole package — one shared
// container per package, reset per test. The os.Exit is delegated to
// RunIntegrationMain so the container-terminate defer runs.
func TestMain(m *testing.M) {
	os.Exit(testutil.RunIntegrationMain(
		m, exchangedb.Migrations, exchangedb.MigrationsDir, exchangedb.MigrationsTable,
		func(pg *sharedb.SharedPostgres) { sharedPG = pg },
	))
}

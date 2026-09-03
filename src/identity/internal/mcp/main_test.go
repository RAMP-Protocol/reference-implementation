//go:build integration

package mcp_test

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

// The MCP adapter needs BOTH backends the identity service runs on: Vault holds
// the agents' signing keys, and Postgres holds the accounts a sign-up provisions
// plus the notes of where each agent has been registered. No tool reads a
// developer record any more — register sends what the AGENT supplies — so the
// second backend is here for provisioning and for those notes.
// Both come up once per package via the shared helper; per-test isolation is a
// Postgres Snapshot/Restore plus a Vault mount reset, and DB-touching tests run
// serially.
const testMount = "identity-kv"

var (
	sharedPG    *sharedb.SharedPostgres
	sharedVault *testutil.SharedVault
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunPostgresVaultMain(m, testutil.PostgresVaultMain{
		Migrations:      identitydb.Migrations,
		MigrationsDir:   identitydb.MigrationsDir,
		MigrationsTable: identitydb.MigrationsTable,
		VaultMount:      testMount,
		Assign: func(pg *sharedb.SharedPostgres, vault *testutil.SharedVault) {
			sharedPG, sharedVault = pg, vault
		},
	}))
}

// acquireTestDB resets the shared Postgres to its migrated baseline and returns a
// fresh pool, once per test (see db.AcquireTestDB for the serial-execution
// contract).
func acquireTestDB(tb testing.TB, ctx context.Context) *pgxpool.Pool {
	tb.Helper()
	return sharedb.AcquireTestDB(tb, ctx, sharedPG)
}

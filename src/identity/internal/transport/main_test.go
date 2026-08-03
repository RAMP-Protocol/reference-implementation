//go:build integration

package transport_test

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

// The identity directory server needs BOTH backends: Vault for the signing keys
// and Postgres for the card metadata. This package therefore keeps a bespoke
// TestMain that brings up one of each (the pattern src/broker/internal/transport
// uses for Postgres+Redis). Both are written once before m.Run and read-only
// thereafter; per-test isolation is Postgres Snapshot/Restore + a Vault mount
// reset, and DB-touching tests run serially.
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
		// The `zitadel` build tag brings up a real Zitadel here; the fast
		// integration tier compiles a no-op (see zitadel_on_test.go /
		// zitadel_off_test.go).
		Extra: maybeStartZitadel,
		Assign: func(pg *sharedb.SharedPostgres, vault *testutil.SharedVault) {
			sharedPG, sharedVault = pg, vault
		},
	}))
}

// acquireTestDB resets the shared Postgres to its migrated baseline and returns a
// fresh pool, once per test (see db.AcquireTestDB for the serial-execution contract).
func acquireTestDB(tb testing.TB, ctx context.Context) *pgxpool.Pool {
	tb.Helper()
	return sharedb.AcquireTestDB(tb, ctx, sharedPG)
}

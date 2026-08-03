//go:build integration

package testutil

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
)

// RunIntegrationMain brings up one shared migrated Postgres for a package's test
// binary, runs the suite, and returns the exit code — the TestMain body every
// shared-Postgres package would otherwise copy. It starts+migrates+snapshots the
// container, hands the handle to assign (so the package records it in its
// package-level var for db.AcquireTestDB), runs the tests, and terminates the
// container afterward. The caller wraps it in os.Exit so the terminate defer runs.
//
// Suites that also need Redis or another shared backend keep a bespoke TestMain
// that brings the extra backend up around m.Run; see src/broker/internal/transport.
// A suite needing Postgres AND Vault — every identity-service package — uses
// RunPostgresVaultMain instead.
func RunIntegrationMain(m *testing.M, migrations fs.FS, dir, table string, assign func(*db.SharedPostgres)) int {
	ctx := context.Background()
	pg, cleanup, err := db.StartSharedPostgresMigrated(ctx, DiscardLogger(), migrations, dir, table)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared postgres: %v\n", err)
		return 1
	}
	defer cleanup()

	assign(pg)
	return m.Run()
}

// RunTigerBeetleMain brings up one shared TigerBeetle container for a package's
// test binary, hands the handle to assign, runs the suite, and returns the exit
// code — the container-only TestMain body a TigerBeetle package would otherwise
// copy. TigerBeetle is append-only (no snapshot/restore), so per-test isolation is
// id salting (SharedTigerBeetle.Salt), not a reset. The caller wraps it in os.Exit
// so the terminate defer runs.
//
// This boots only the container; it stays free of the CGO tigerbeetle-go client
// (the client lives exchange-side). A suite that also needs a client or Postgres
// keeps a bespoke TestMain (see src/exchange/internal/transport).
func RunTigerBeetleMain(m *testing.M, assign func(*SharedTigerBeetle)) int {
	ctx := context.Background()
	shared, cleanup, err := StartSharedTigerBeetle(ctx, DiscardLogger())
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared tigerbeetle: %v\n", err)
		return 1
	}
	defer cleanup()

	assign(shared)
	return m.Run()
}

// PostgresVaultMain configures RunPostgresVaultMain.
type PostgresVaultMain struct {
	// Migrations, MigrationsDir, and MigrationsTable locate the schema applied to
	// the shared Postgres before the snapshot each test is restored to.
	Migrations      fs.FS
	MigrationsDir   string
	MigrationsTable string

	// VaultMount is the KV v2 mount the suite writes keys to. Reset replaces it
	// wholesale between tests.
	VaultMount string

	// Extra brings up any further backend this package needs and returns its
	// cleanup, which runs before the shared containers are torn down. Optional —
	// the identity transport suite uses it for the real-Zitadel tier, which is
	// compiled out of the fast tier entirely.
	Extra func(context.Context, *slog.Logger) func()

	// Assign records the started handles in the package's shared vars, so
	// per-test acquire and reset can reach them.
	Assign func(*db.SharedPostgres, *SharedVault)
}

// RunPostgresVaultMain brings up one shared migrated Postgres AND one shared Vault
// for a package's test binary, runs the suite, and returns the exit code.
//
// It exists because both backends are needed together by every identity-service
// package that touches keys: Vault custodies the signing keys, Postgres holds the
// records that name them. Bringing them up per package rather than per test is the
// binding rule (a container per test does not scale); doing it in one shared place
// rather than per package is what keeps the two suites from drifting apart on
// startup order, mount naming, or cleanup.
//
// Per-test isolation is the caller's: Postgres Snapshot/Restore via
// db.AcquireTestDB, and (*SharedVault).Reset for the mount. The caller wraps this
// in os.Exit so the terminate defers actually run.
func RunPostgresVaultMain(m *testing.M, cfg PostgresVaultMain) int {
	ctx := context.Background()
	logger := DiscardLogger()

	pg, pgCleanup, err := db.StartSharedPostgresMigrated(
		ctx, logger, cfg.Migrations, cfg.MigrationsDir, cfg.MigrationsTable,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared postgres: %v\n", err)
		return 1
	}
	defer pgCleanup()

	vault, vaultCleanup, err := StartSharedVault(ctx, logger, cfg.VaultMount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared vault: %v\n", err)
		return 1
	}
	defer vaultCleanup()

	if cfg.Extra != nil {
		defer cfg.Extra(ctx, logger)()
	}

	cfg.Assign(pg, vault)
	return m.Run()
}

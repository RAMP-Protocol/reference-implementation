//go:build integration

// Package servicetest holds the shared Postgres lifecycle for the service
// package's integration tests. It is a separate package because that test suite
// spans BOTH package service (internal — metadata_persist needs the unexported
// entryFromProto) and package service_test (external — catalog_pushtx): a bridge
// package both can import is the only way they share one container per the
// one-container-per-package rule (Testing Doctrine §11). TestMain assigns the
// migrated handle here once; every test acquires its database through AcquireTestDB.
package servicetest

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
)

// sharedPG is the package's single migrated Postgres, assigned once by TestMain
// (via Assign) and read-only thereafter.
var sharedPG *sharedb.SharedPostgres

// Assign records the shared container handle; call it from TestMain via
// testutil.RunIntegrationMain.
func Assign(pg *sharedb.SharedPostgres) { sharedPG = pg }

// AcquireTestDB resets the shared Postgres to its migrated baseline and returns a
// fresh pool — once per test, at the start of setup. DB-touching tests run serially
// (Reset drops and recreates the database; see db.AcquireTestDB).
func AcquireTestDB(tb testing.TB, ctx context.Context) *pgxpool.Pool {
	tb.Helper()
	return sharedb.AcquireTestDB(tb, ctx, sharedPG)
}

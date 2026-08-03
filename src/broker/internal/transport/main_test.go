//go:build integration

package transport_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the database/sql "pgx" driver used by testcontainers Snapshot/Restore

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	brokerdb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db"
)

// sharedPG and sharedRedis are the package's single Postgres and Redis
// containers, brought up once by TestMain and reset between tests (Postgres via
// Snapshot/Restore, Redis via FLUSHDB). Written once before m.Run and read-only
// thereafter, so the serial integration tests need no synchronization. Sharing
// one container per backend replaces 14 per-test Postgres and 7 per-test Redis
// startups.
var (
	sharedPG    *sharedb.SharedPostgres
	sharedRedis *testutil.SharedRedis
)

// TestMain brings up one Postgres and one Redis container for the whole package.
// The os.Exit is delegated to runIntegrationMain so the container-terminate
// defers run (os.Exit would skip them).
func TestMain(m *testing.M) {
	os.Exit(runIntegrationMain(m))
}

func runIntegrationMain(m *testing.M) int {
	ctx := context.Background()
	logger := testutil.DiscardLogger()

	pg, pgCleanup, err := sharedb.StartSharedPostgresMigrated(
		ctx, logger, brokerdb.Migrations, brokerdb.MigrationsDir, brokerdb.MigrationsTable,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared postgres: %v\n", err)
		return 1
	}
	defer pgCleanup()

	rdb, redisCleanup, err := testutil.StartSharedRedis(ctx, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared redis: %v\n", err)
		return 1
	}
	defer redisCleanup()

	sharedPG = pg
	sharedRedis = rdb
	return m.Run()
}

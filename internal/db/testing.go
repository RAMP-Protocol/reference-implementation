package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// StartPostgres spins a postgres:16-alpine container for a test, returning
// a DSN string. The container is terminated when the test ends.
func StartPostgres(tb testing.TB, ctx context.Context) string {
	tb.Helper()
	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("ramp"),
		tcpostgres.WithUsername("ramp"),
		tcpostgres.WithPassword("ramp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		tb.Fatalf("start postgres: %v", err)
	}
	tb.Cleanup(func() {
		if termErr := container.Terminate(context.Background()); termErr != nil {
			tb.Logf("terminate postgres: %v", termErr)
		}
	})
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		tb.Fatalf("connection string: %v", err)
	}
	return dsn
}

// OpenForTest opens a pool against dsn with short timeouts suitable for tests.
func OpenForTest(tb testing.TB, ctx context.Context, dsn string) *pgxpool.Pool {
	tb.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		tb.Fatalf("open pool: %v", err)
	}
	tb.Cleanup(pool.Close)
	if pingErr := pool.Ping(ctx); pingErr != nil {
		tb.Fatalf("ping: %v", pingErr)
	}
	return pool
}

// NewSilentLogger returns a logger suitable for tests (discards output).
var _ = fmt.Sprintf

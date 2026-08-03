//go:build integration

package db

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// postgresRunOptions is the single source of truth for the testcontainers
// postgres run configuration. Both StartPostgres (per-test container) and
// StartSharedPostgres (one container per package) call it, so the option list
// lives in exactly one place.
//
// WithSQLDriver("pgx") makes the module's Snapshot/Restore use a database/sql
// "pgx" connection — registered by a blank import of jackc/pgx/v5/stdlib in the
// test binary — instead of the unregistered default "postgres" driver, which
// would otherwise force a slow per-statement `docker exec psql` fallback.
//
// The wait strategy combines the readiness LOG with ForListeningPort: a log-only
// wait lets Run return as soon as Postgres prints "ready", which under Docker
// load can be BEFORE the host port mapping is published — ConnectionString then
// fails with `port "5432/tcp" not found`. Waiting on the listening port forces
// testcontainers to confirm the mapped port is reachable before Run returns.
// Timeouts are generous (60s) to tolerate a busy shared Docker daemon.
func postgresRunOptions() []testcontainers.ContainerCustomizer {
	return []testcontainers.ContainerCustomizer{
		tcpostgres.WithDatabase("ramp"),
		tcpostgres.WithUsername("ramp"),
		tcpostgres.WithPassword("ramp"),
		tcpostgres.WithSQLDriver("pgx"),
		testcontainers.WithWaitStrategy(
			wait.ForAll(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(60*time.Second),
				wait.ForListeningPort("5432/tcp").
					WithStartupTimeout(60*time.Second),
			),
		),
	}
}

// runPostgres starts a postgres:16-alpine container and returns it with its DSN.
// Shared by StartPostgres and StartSharedPostgres so the run + connection-string
// boilerplate exists in one place.
func runPostgres(ctx context.Context) (*tcpostgres.PostgresContainer, string, error) {
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine", postgresRunOptions()...)
	if err != nil {
		return nil, "", fmt.Errorf("start postgres: %w", err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(context.Background()) // best-effort; Ryuk backstops
		return nil, "", fmt.Errorf("connection string: %w", err)
	}
	return container, dsn, nil
}

// StartPostgres spins a postgres:16-alpine container for a test, returning a DSN
// string. The container is terminated when the test ends. Prefer the shared
// per-package container (StartSharedPostgres + a TestMain) for large suites; this
// per-test helper remains for packages with only a handful of integration tests.
func StartPostgres(tb testing.TB, ctx context.Context) string {
	tb.Helper()
	container, dsn, err := runPostgres(ctx)
	if err != nil {
		tb.Fatalf("%v", err)
	}
	tb.Cleanup(func() {
		if termErr := container.Terminate(context.Background()); termErr != nil {
			tb.Logf("terminate postgres: %v", termErr)
		}
	})
	return dsn
}

// SharedPostgres is a single postgres:16-alpine container, migrated once and
// reset to its post-migration baseline between tests via the testcontainers
// snapshot/restore mechanism (native Postgres template database). It is built
// from a package's TestMain so container startup + migrations are paid once per
// package run instead of once per test.
//
// Usage (TestMain): StartSharedPostgres -> db.Migrate(...) -> Snapshot. Per test:
// Reset (restore baseline) -> OpenForTest(DSN). Tests MUST run serially: Reset
// drops and recreates the shared database, so it cannot overlap a sibling test.
type SharedPostgres struct {
	container *tcpostgres.PostgresContainer
	// DSN addresses the shared database; it is stable across Reset because
	// Restore recreates the same database name from the template.
	DSN string
}

// StartSharedPostgres runs one container and returns a handle, a terminate func
// for the caller (TestMain) to defer, and any startup error. It does NOT migrate
// or snapshot — the caller migrates via Migrate (which holds no pool open) and
// then calls Snapshot, so the snapshot's CREATE DATABASE ... WITH TEMPLATE has
// zero open connections to the source database.
func StartSharedPostgres(ctx context.Context, logger *slog.Logger) (*SharedPostgres, func(), error) {
	container, dsn, err := runPostgres(ctx)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		if termErr := container.Terminate(context.Background()); termErr != nil {
			logger.Warn("terminate shared postgres", "err", termErr)
		}
	}
	return &SharedPostgres{container: container, DSN: dsn}, cleanup, nil
}

// StartSharedPostgresMigrated runs one shared container, applies migrations, and
// snapshots the migrated baseline — the full once-per-package setup behind a
// single call for a package's TestMain. It composes StartSharedPostgres, Migrate,
// and Snapshot so callers need not repeat the sequence or remember its ordering
// constraint: migrations run via Migrate (which opens and closes its own
// connection) rather than Setup (which returns an open pool), leaving zero
// sessions on the source database so Snapshot's CREATE DATABASE ... WITH TEMPLATE
// succeeds. The returned cleanup terminates the container; the caller (TestMain)
// defers it. On any failure after the container starts, the container is
// terminated before returning so it does not leak.
func StartSharedPostgresMigrated(
	ctx context.Context, logger *slog.Logger, migrations fs.FS, dir, table string,
) (*SharedPostgres, func(), error) {
	pg, cleanup, err := StartSharedPostgres(ctx, logger)
	if err != nil {
		return nil, nil, err
	}
	if migErr := Migrate(migrations, dir, pg.DSN, table, logger); migErr != nil {
		cleanup()
		return nil, nil, fmt.Errorf("migrate shared postgres: %w", migErr)
	}
	if snapErr := pg.Snapshot(ctx); snapErr != nil {
		cleanup()
		return nil, nil, snapErr
	}
	return pg, cleanup, nil
}

// Snapshot records the current (migrated) database as the restore baseline.
// Call once, after migrations and before any test runs.
func (s *SharedPostgres) Snapshot(ctx context.Context) error {
	if err := s.container.Snapshot(ctx); err != nil {
		return fmt.Errorf("snapshot postgres: %w", err)
	}
	return nil
}

// Reset restores the shared database to the snapshot baseline, discarding every
// row written by the previous test. Call at the start of each test's setup,
// before opening that test's pool. Reset-at-start (rather than in cleanup) keeps
// the suite robust against a test that panics without running its cleanup.
func (s *SharedPostgres) Reset(ctx context.Context) error {
	if err := s.container.Restore(ctx); err != nil {
		return fmt.Errorf("restore postgres: %w", err)
	}
	return nil
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

// AcquireTestDB resets the shared Postgres to its migrated baseline and returns a
// fresh pool bound to it. Call it exactly once per test, at the start of setup:
// Reset drops and recreates the shared database, so a second call within the same
// test would discard everything the first call seeded. Reset-at-start (rather than
// in cleanup) keeps the suite robust against a test that panics. DB-touching tests
// must run serially — Reset cannot overlap a sibling (see SharedPostgres).
func AcquireTestDB(tb testing.TB, ctx context.Context, pg *SharedPostgres) *pgxpool.Pool {
	tb.Helper()
	if err := pg.Reset(ctx); err != nil {
		tb.Fatalf("reset shared db: %v", err)
	}
	return OpenForTest(tb, ctx, pg.DSN)
}

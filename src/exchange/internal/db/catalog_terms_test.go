//go:build integration

package db_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
)

// migratedDSN starts this package's per-test Postgres and migrates it to head,
// returning the DSN. It is the four-statement preamble every migration test in
// this package opened with, in one place.
//
// Doctrine carve-out, recorded deliberately: the package-wide rule is ONE shared
// container per package reset per test, and these tests are the exception. They
// migrate UP and back DOWN to assert a migration reverses cleanly, which a shared
// post-migration snapshot cannot serve — a snapshot restores one fixed schema
// version, and that is precisely the variable under test. The cost of the
// exception is a container per test, so it is bounded by this helper: switching
// the package to a TestMain later is a change to this function, not to every
// file that calls it.
func migratedDSN(t *testing.T, ctx context.Context) string {
	t.Helper()
	dsn := sharedb.StartPostgres(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := sharedb.Migrate(
		exchangedb.Migrations, exchangedb.MigrationsDir, dsn, exchangedb.MigrationsTable, logger,
	); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	return dsn
}

// existsProbe runs a one-shot `SELECT EXISTS (...)` schema query and returns the
// boolean. Shared by the column/table probes so the pool + scan boilerplate lives
// in one place.
func existsProbe(t *testing.T, ctx context.Context, dsn, query string, args ...any) bool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	var exists bool
	if err := pool.QueryRow(ctx, query, args...).Scan(&exists); err != nil {
		t.Fatalf("exists probe: %v", err)
	}
	return exists
}

// hasColumn reports whether ramp.catalog has the given column.
func hasColumn(t *testing.T, ctx context.Context, dsn, col string) bool {
	t.Helper()
	return hasColumnIn(t, ctx, dsn, "catalog", col)
}

// hasColumnIn reports whether the given ramp table has the given column.
func hasColumnIn(t *testing.T, ctx context.Context, dsn, table, col string) bool {
	t.Helper()
	return existsProbe(t, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'ramp' AND table_name = $1 AND column_name = $2
		)`, table, col)
}

// hasTable reports whether the ramp schema has the given table.
func hasTable(t *testing.T, ctx context.Context, dsn, table string) bool {
	t.Helper()
	return existsProbe(t, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'ramp' AND table_name = $1
		)`, table)
}

// migrator builds a golang-migrate instance over the embedded exchange
// migrations, mirroring internal/db.Migrate's pgx5 + tracking-table annotation.
func migrator(t *testing.T, dsn string) *migrate.Migrate {
	t.Helper()
	src, err := iofs.New(exchangedb.Migrations, exchangedb.MigrationsDir)
	if err != nil {
		t.Fatalf("iofs: %v", err)
	}
	a := dsn
	a = "pgx5://" + strings.TrimPrefix(strings.TrimPrefix(a, "postgresql://"), "postgres://")
	sep := "?"
	if strings.Contains(a, "?") {
		sep = "&"
	}
	a = fmt.Sprintf("%s%ssearch_path=public&x-migrations-table=%s", a, sep, exchangedb.MigrationsTable)
	m, err := migrate.NewWithSourceInstance("iofs", src, a)
	if err != nil {
		t.Fatalf("migrate new: %v", err)
	}
	return m
}

// TestCatalogTermsMigration verifies the EXPAND/CONTRACT pair that moves
// ramp.catalog off the legacy licensing_rules column onto terms:
//   - 000010 (EXPAND) adds terms.
//   - 000011 (CONTRACT) drops licensing_rules.
//
// At head both invariants hold (terms present, licensing_rules gone). Stepping
// down reverses them in order: -1 restores licensing_rules (still has terms),
// -1 again removes terms — proving each migration's down is the exact inverse
// of its up.
func TestCatalogTermsMigration(t *testing.T) {
	ctx := context.Background()
	// Up to head — terms added (000010), licensing_rules dropped (000011).
	dsn := migratedDSN(t, ctx)
	if !hasColumn(t, ctx, dsn, "terms") {
		t.Fatal("after up: ramp.catalog is missing the terms column")
	}
	if hasColumn(t, ctx, dsn, "licensing_rules") {
		t.Fatal("after up: ramp.catalog still has the licensing_rules column")
	}

	m := migrator(t, dsn)
	defer m.Close()

	// Navigate to explicit schema versions instead of counting Steps(-1) from a
	// moving head: every migration added above the EXPAND/CONTRACT pair (000012
	// catalog_uri UNIQUE, 000013 denial_reason enum add, and any future one)
	// would otherwise shift the step math and break this test. Migrate(10)
	// reverses everything above version 10 — including the 000011 CONTRACT —
	// leaving the pre-CONTRACT state: terms present (000010 up) and
	// licensing_rules restored (000011 down).
	if err := m.Migrate(10); err != nil {
		t.Fatalf("migrate to version 10 (reverse 000011 CONTRACT): %v", err)
	}
	if !hasColumn(t, ctx, dsn, "licensing_rules") {
		t.Fatal("after down 000011: licensing_rules was not restored")
	}
	if !hasColumn(t, ctx, dsn, "terms") {
		t.Fatal("after down 000011: terms column disappeared prematurely")
	}

	// Migrate(9) reverses the 000010 EXPAND: the terms column is removed.
	if err := m.Migrate(9); err != nil {
		t.Fatalf("migrate to version 9 (reverse 000010 EXPAND): %v", err)
	}
	if hasColumn(t, ctx, dsn, "terms") {
		t.Fatal("after down 000010: ramp.catalog still has the terms column")
	}
}

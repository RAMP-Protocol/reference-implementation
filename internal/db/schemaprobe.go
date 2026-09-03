//go:build integration

package db

import (
	"context"
	"io/fs"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SchemaProbe answers structural questions about a migrated test database — does
// this table exist, does it have this column, what default did that column come
// back at — and builds the golang-migrate handle a migration test uses to step
// the schema down and back up.
//
// A migration test proves that a down migration is the exact inverse of its up:
// assert the shape at head, Migrate to an explicit earlier version, assert the
// shape reversed. Every service's migrations need the same questions asked, so
// the probe takes the schema it looks in and the migration source it steps as
// fields rather than hardcoding one service's. Every TYPED question below is keyed
// on Schema, so pointing a probe at a different schema moves all of them together.
// Exists is the exception and stays behind: it runs the caller's own SQL, which
// names the schema itself — the Exchange's migration tests reach it through
// regclass literals such as 'ramp.transaction_evidence'.
//
// It lives beside Migrate and the shared-container helpers, behind the same
// integration build tag, because its three fields are exactly Migrate's
// parameters and it drives the same URL builder the service's startup migration
// uses. Nothing here is compiled into a service binary.
//
// Reads run over their own short-lived pool, outside any pool the test holds, so
// a probe never sees a caller's open transaction.
type SchemaProbe struct {
	// Schema is the information_schema.table_schema the table and column probes
	// look in — "ramp" for the Exchange, "identity" for the identity service.
	Schema string
	// Migrations, Dir and Table locate the migration set Migrator steps and the
	// tracking table it reads the current version from. They are the same three
	// values the service passes to Migrate at startup.
	Migrations fs.FS
	Dir        string
	Table      string
}

// Exists runs a one-shot `SELECT EXISTS (...)` schema query and returns the
// boolean, so the pool and scan boilerplate is written once. Use it for a
// catalog question the typed probes below do not cover — a trigger definition, a
// constraint shape, an index. A question about a table or a column in the
// probe's own schema belongs on the probe instead, so it follows Schema. A query
// that is not shaped as a single-boolean SELECT fails the test rather than
// returning false.
func (p SchemaProbe) Exists(tb testing.TB, ctx context.Context, dsn, query string, args ...any) bool {
	tb.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		tb.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	var exists bool
	if err := pool.QueryRow(ctx, query, args...).Scan(&exists); err != nil {
		tb.Fatalf("exists probe: %v", err)
	}
	return exists
}

// HasTable reports whether the probe's schema has the given table.
func (p SchemaProbe) HasTable(tb testing.TB, ctx context.Context, dsn, table string) bool {
	tb.Helper()
	return p.Exists(tb, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = $1 AND table_name = $2
		)`, p.Schema, table)
}

// HasColumn reports whether the given table in the probe's schema has the given
// column. information_schema hides a dropped column, so this answers false for a
// column that DROP COLUMN has removed even though its bytes are still on disk.
func (p SchemaProbe) HasColumn(tb testing.TB, ctx context.Context, dsn, table, col string) bool {
	tb.Helper()
	return p.Exists(tb, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = $1 AND table_name = $2 AND column_name = $3
		)`, p.Schema, table, col)
}

// HasColumnDefault reports whether the given column declares want as its
// default. Spell want the way Postgres renders it in
// information_schema.column_default, which is not always the way the migration
// wrote it. A down migration that restores a column with ADD COLUMN ... DEFAULT
// backfills every existing row with that default, so this is what a restored row
// holds.
func (p SchemaProbe) HasColumnDefault(tb testing.TB, ctx context.Context, dsn, table, col, want string) bool {
	tb.Helper()
	return p.Exists(tb, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = $1 AND table_name = $2
			  AND column_name = $3 AND column_default = $4
		)`, p.Schema, table, col, want)
}

// HasColumnNotNull reports whether the given column is declared NOT NULL. It is a
// separate question from HasColumnDefault: a column restored with a DEFAULT but
// without NOT NULL answers true to the default probe and false to this one, and the
// two together are what "the down migration restores the column as it was" means. A
// column that is not there at all answers false.
func (p SchemaProbe) HasColumnNotNull(tb testing.TB, ctx context.Context, dsn, table, col string) bool {
	tb.Helper()
	return p.Exists(tb, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = $1 AND table_name = $2
			  AND column_name = $3 AND is_nullable = 'NO'
		)`, p.Schema, table, col)
}

// HasColumnType reports whether the given column has want as its SQL type. Spell
// want the way information_schema.columns renders it in data_type, which is the
// standard's spelling and not always the one the migration wrote: a column
// declared timestamptz comes back as "timestamp with time zone". Type is a
// separate question from default — a column restored as timestamp rather than
// timestamptz still renders now() as its default — so a test that means "the same
// column came back" asks both.
func (p SchemaProbe) HasColumnType(tb testing.TB, ctx context.Context, dsn, table, col, want string) bool {
	tb.Helper()
	return p.Exists(tb, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = $1 AND table_name = $2
			  AND column_name = $3 AND data_type = $4
		)`, p.Schema, table, col, want)
}

// HasFunction reports whether the probe's schema has a function with the given
// name, whatever arguments it takes. It reads the pg_proc catalog joined to
// pg_namespace, so the question follows Schema like the ones above rather than
// naming a schema of its own.
func (p SchemaProbe) HasFunction(tb testing.TB, ctx context.Context, dsn, name string) bool {
	tb.Helper()
	return p.Exists(tb, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM pg_proc p
			JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = $1 AND p.proname = $2
		)`, p.Schema, name)
}

// ColumnComesAfter reports whether col sits at a later ordinal position than
// other in the given table. ADD COLUMN appends and Postgres cannot reorder, so a
// migration test uses this to pin where a restored column actually lands. A
// column that is not there at all answers false rather than failing the probe,
// so a down migration that drops a column reports the missing column once and
// does not also die here on a NULL position.
func (p SchemaProbe) ColumnComesAfter(tb testing.TB, ctx context.Context, dsn, table, col, other string) bool {
	tb.Helper()
	return p.Exists(tb, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns a
			JOIN information_schema.columns b
			  ON b.table_schema = a.table_schema AND b.table_name = a.table_name
			WHERE a.table_schema = $1 AND a.table_name = $2
			  AND a.column_name = $3 AND b.column_name = $4
			  AND a.ordinal_position > b.ordinal_position
		)`, p.Schema, table, col, other)
}

// Migrator builds a golang-migrate instance over the probe's migrations, pointed
// at dsn, and closes it when the test ends. The URL comes from migrateURL, the
// same builder the service's startup migration uses, so a test cannot step a
// differently-configured schema than production runs.
//
// The close is registered here because this helper already has tb. Left to the
// caller it became the same deferred close written out in every migration test,
// which is a helper handing back a resource without owning its lifecycle.
func (p SchemaProbe) Migrator(tb testing.TB, dsn string) *migrate.Migrate {
	tb.Helper()
	m, err := newMigrator(p.Migrations, p.Dir, dsn, p.Table)
	if err != nil {
		tb.Fatalf("migrator: %v", err)
	}
	tb.Cleanup(func() { _, _ = m.Close() })
	return m
}

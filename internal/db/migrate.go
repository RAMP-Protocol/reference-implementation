package db

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // pgx5 driver registration
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// migrateURL rewrites a Postgres DSN into the URL golang-migrate needs: the pgx5
// driver, a pinned search_path, and the caller's tracking table. Anything that
// drives golang-migrate against a DSN this repo produced goes through here — the
// startup migration below and SchemaProbe.Migrator — so a migration run and a
// test that steps the same schema up and down cannot disagree on how the URL is
// built.
//
// tableName is optional; an empty one leaves migrate on its default table.
func migrateURL(dsn, tableName string) string {
	// Rewrite the URL scheme so golang-migrate uses the pgx5 driver rather than
	// its legacy lib/pq-based "postgres" driver.
	annotatedDSN := dsn
	switch {
	case strings.HasPrefix(annotatedDSN, "postgres://"):
		annotatedDSN = "pgx5://" + strings.TrimPrefix(annotatedDSN, "postgres://")
	case strings.HasPrefix(annotatedDSN, "postgresql://"):
		annotatedDSN = "pgx5://" + strings.TrimPrefix(annotatedDSN, "postgresql://")
	}
	// Pin the search_path so migrate's unqualified tracking-table reference always
	// resolves to `public`, even when a migration (e.g. CREATE SCHEMA ramp) would
	// otherwise shift the default. Without this, repeated restarts can produce
	// duplicate schema_migrations_* tables in different schemas.
	if !strings.Contains(annotatedDSN, "search_path=") {
		annotatedDSN += querySep(annotatedDSN) + "search_path=public"
	}
	if tableName != "" {
		annotatedDSN += querySep(annotatedDSN) + "x-migrations-table=" + tableName
	}
	return annotatedDSN
}

// querySep returns the character that starts the next query parameter on url.
func querySep(url string) string {
	if strings.Contains(url, "?") {
		return "&"
	}
	return "?"
}

// newMigrator builds a golang-migrate instance over an embedded migration set,
// pointed at dsn and tracking its version in tableName. It is the one place the
// source instance and the annotated URL are assembled, so an option added to
// either reaches the service's startup migration and the test-side probe that
// steps a schema backwards. The caller closes the instance.
func newMigrator(migrations fs.FS, subdir, dsn, tableName string) (*migrate.Migrate, error) {
	src, err := iofs.New(migrations, subdir)
	if err != nil {
		return nil, fmt.Errorf("iofs source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateURL(dsn, tableName))
	if err != nil {
		return nil, fmt.Errorf("migrate new: %w", err)
	}
	return m, nil
}

// Migrate applies up-migrations from an embedded fs onto the given DSN.
// tableName controls where migration state is tracked (use per-schema names so
// each service owns its own tracking table).
func Migrate(migrations fs.FS, subdir, dsn, tableName string, logger *slog.Logger) error {
	m, err := newMigrator(migrations, subdir, dsn, tableName)
	if err != nil {
		return err
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			logger.Warn("migrate source close", "err", srcErr)
		}
		if dbErr != nil {
			logger.Warn("migrate db close", "err", dbErr)
		}
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	version, dirty, verErr := m.Version()
	if verErr != nil && !errors.Is(verErr, migrate.ErrNilVersion) {
		return fmt.Errorf("migrate version: %w", verErr)
	}
	logger.Info("migrations applied", "version", version, "dirty", dirty, "table", tableName)
	return nil
}

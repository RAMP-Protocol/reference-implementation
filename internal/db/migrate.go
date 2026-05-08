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

// Migrate applies up-migrations from an embedded fs onto the given DSN.
// tableName controls where migration state is tracked (use per-schema names so
// each service owns its own tracking table).
func Migrate(migrations fs.FS, subdir, dsn, tableName string, logger *slog.Logger) error {
	src, err := iofs.New(migrations, subdir)
	if err != nil {
		return fmt.Errorf("iofs source: %w", err)
	}

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
		sep := "?"
		if strings.Contains(annotatedDSN, "?") {
			sep = "&"
		}
		annotatedDSN = fmt.Sprintf("%s%ssearch_path=public", annotatedDSN, sep)
	}
	if tableName != "" {
		sep := "&"
		if !strings.Contains(annotatedDSN, "?") {
			sep = "?"
		}
		annotatedDSN = fmt.Sprintf("%s%sx-migrations-table=%s", annotatedDSN, sep, tableName)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, annotatedDSN)
	if err != nil {
		return fmt.Errorf("migrate new: %w", err)
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

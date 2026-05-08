package db

import (
	"context"
	"io/fs"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SetupOptions bundles the inputs for Setup.
type SetupOptions struct {
	DSN             string
	Migrations      fs.FS
	MigrationsDir   string
	MigrationsTable string
	PoolConfig      Config
}

// Setup opens a pool and applies embedded migrations. If DSN is empty it
// returns (nil, nil) — callers can operate DB-less when configuration is
// absent (useful for early demo phases).
func Setup(ctx context.Context, opts SetupOptions, logger *slog.Logger) (*pgxpool.Pool, error) {
	if opts.DSN == "" {
		logger.Info("database disabled: no DSN set")
		return nil, nil
	}
	cfg := opts.PoolConfig
	cfg.DSN = opts.DSN
	pool, err := Open(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	if opts.Migrations != nil {
		if migErr := Migrate(opts.Migrations, opts.MigrationsDir, opts.DSN, opts.MigrationsTable, logger); migErr != nil {
			pool.Close()
			return nil, migErr
		}
	}
	return pool, nil
}

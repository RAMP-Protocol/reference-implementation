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
// returns (nil, nil) rather than deciding for the caller: the shared helper
// stays neutral so each service picks its own contract. Every caller in this
// repository refuses an empty DSN — either by rejecting it before calling or by
// treating the nil pool as a hard error — so nothing here runs without a
// database.
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

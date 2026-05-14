package db

import (
	"context"
	"fmt"
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

// Setup opens a pool and applies embedded migrations. Returns an error if DSN
// is empty — callers must supply a non-empty DSN.
func Setup(ctx context.Context, opts SetupOptions, logger *slog.Logger) (*pgxpool.Pool, error) {
	if opts.DSN == "" {
		return nil, fmt.Errorf("db: DSN is required")
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

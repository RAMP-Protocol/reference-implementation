package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
	sordb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor/db"
)

// newPostgresSoRAdapter builds the Postgres-backed SoR adapter from the
// environment, wrapped in the short-TTL IsActive read cache. Mirroring the
// billing constructor, every env var is validated BEFORE the pool opens, so a
// misconfiguration fails fast without leaking a socket. The returned func()
// closes the SoR's pool on shutdown.
//
// The SoR runs against its OWN logical database — EXCHANGE_SOR_DSN opens a
// SECOND pool, distinct from EXCHANGE_DSN. The app applies the SoR migration
// sequence at boot against a pre-provisioned database; it never CREATE
// DATABASEs (AC #5 / plan §5 Q1).
//
// Environment variables (backend config under the EXCHANGE_SOR_ prefix, matching
// the billing convention; the RAMP_SOR_ADAPTER selector lives in main.go):
//   - EXCHANGE_SOR_DSN: the SoR database DSN (required; empty fails boot).
//   - EXCHANGE_SOR_CACHE_TTL: IsActive read-cache lifetime (Go duration,
//     default 30s via sor.DefaultCacheTTL); an unparseable value fails boot.
func newPostgresSoRAdapter(ctx context.Context, logger *slog.Logger) (sor.Adapter, func(), error) {
	dsn := runhttp.EnvOr("EXCHANGE_SOR_DSN", "")
	if dsn == "" {
		return nil, nil, fmt.Errorf("sor: EXCHANGE_SOR_DSN is required for RAMP_SOR_ADAPTER=postgres")
	}
	ttl := sor.DefaultCacheTTL
	if raw := runhttp.EnvOr("EXCHANGE_SOR_CACHE_TTL", ""); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("sor: invalid EXCHANGE_SOR_CACHE_TTL: %w", err)
		}
		ttl = parsed
	}

	// All settings are checked above, so the database connection is only
	// opened once the config is known to be good. db.Setup opens the pool,
	// runs the migrations, and closes the pool again if a migration fails.
	// (db.Setup would silently skip an empty DSN, but the check above already
	// rejected that case.)
	pool, err := db.Setup(ctx, db.SetupOptions{
		DSN:             dsn,
		Migrations:      sordb.Migrations,
		MigrationsDir:   sordb.MigrationsDir,
		MigrationsTable: sordb.MigrationsTable,
	}, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("sor: setup database: %w", err)
	}

	adapter := sor.NewCachingAdapter(sor.NewPostgresAdapter(db.PoolRunner{Pool: pool}), ttl, clock.System{})
	logger.Info("sor adapter: postgres", "cache_ttl", ttl)
	return adapter, pool.Close, nil
}

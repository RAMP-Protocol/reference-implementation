// Package db provides shared database wiring: pgxpool construction with a
// slog-backed query tracer, context-aware shutdown, and a generic migration
// runner. Service-specific embedded migrations live under each service's
// internal/db package.
package db

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/tracelog"
)

// Config captures pool-level tunables. Zero values fall back to sensible defaults.
type Config struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	HealthCheckFreq time.Duration
}

// Open constructs a pgxpool.Pool wired to a slog-based tracer.
// Caller owns the lifecycle; call pool.Close() on shutdown.
func Open(ctx context.Context, cfg Config, logger *slog.Logger) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	if cfg.MaxConns > 0 {
		pc.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		pc.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		pc.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		pc.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.HealthCheckFreq > 0 {
		pc.HealthCheckPeriod = cfg.HealthCheckFreq
	}
	pc.ConnConfig.Tracer = &tracelog.TraceLog{
		Logger:   slogAdapter{logger: logger},
		LogLevel: tracelog.LogLevelWarn,
	}

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// slogAdapter bridges pgx's tracelog interface to the stdlib slog logger.
type slogAdapter struct {
	logger *slog.Logger
}

func (s slogAdapter) Log(ctx context.Context, level tracelog.LogLevel, msg string, data map[string]any) {
	attrs := make([]any, 0, 2*len(data))
	for k, v := range data {
		attrs = append(attrs, k, v)
	}
	switch level {
	case tracelog.LogLevelTrace, tracelog.LogLevelDebug:
		s.logger.DebugContext(ctx, msg, attrs...)
	case tracelog.LogLevelInfo:
		s.logger.InfoContext(ctx, msg, attrs...)
	case tracelog.LogLevelWarn:
		s.logger.WarnContext(ctx, msg, attrs...)
	case tracelog.LogLevelError:
		s.logger.ErrorContext(ctx, msg, attrs...)
	default:
		s.logger.InfoContext(ctx, msg, attrs...)
	}
}

// Ping is a thin convenience for health endpoints.
func Ping(ctx context.Context, pool *pgxpool.Pool) error {
	return pool.Ping(ctx)
}

// WithTx runs fn inside a transaction. Commits on nil error, rolls back otherwise.
// Thin wrapper around pgx.BeginFunc to keep call sites terse.
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, pool, fn)
}

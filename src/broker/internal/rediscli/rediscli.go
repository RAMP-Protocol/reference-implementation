// Package rediscli wires a go-redis client for the Broker. Returns nil when
// no DSN is configured so callers can fall back to in-process behavior
// (demo-friendly).
package rediscli

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// Setup opens a redis client using the given DSN (redis://...), pings it once
// to confirm reachability, and returns the client. When dsn is empty it
// returns (nil, nil) — the Broker operates in Redis-less fallback mode.
func Setup(ctx context.Context, dsn string, logger *slog.Logger) (*redis.Client, error) {
	if dsn == "" {
		logger.Info("redis disabled: no REDIS_URL set")
		return nil, nil
	}
	opts, err := redis.ParseURL(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse redis dsn: %w", err)
	}
	client := redis.NewClient(opts)
	if pingErr := client.Ping(ctx).Err(); pingErr != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", pingErr)
	}
	logger.Info("redis ready", "addr", opts.Addr)
	return client, nil
}

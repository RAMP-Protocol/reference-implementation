//go:build integration

package testutil

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

// runRedis starts a redis:7-alpine container and returns it with a connected
// client. Shared by StartRedis (per-test) and StartSharedRedis (one per package)
// so the run + connect boilerplate exists in exactly one place.
func runRedis(ctx context.Context) (*tcredis.RedisContainer, *redis.Client, error) {
	c, err := tcredis.Run(
		ctx, "redis:7-alpine",
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("start redis: %w", err)
	}
	dsn, err := c.ConnectionString(ctx)
	if err != nil {
		_ = c.Terminate(context.Background()) // best-effort; Ryuk backstops
		return nil, nil, fmt.Errorf("redis conn string: %w", err)
	}
	opts, err := redis.ParseURL(dsn)
	if err != nil {
		_ = c.Terminate(context.Background())
		return nil, nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opts)
	if pingErr := client.Ping(ctx).Err(); pingErr != nil {
		_ = client.Close()
		_ = c.Terminate(context.Background())
		return nil, nil, fmt.Errorf("redis ping: %w", pingErr)
	}
	return c, client, nil
}

// StartRedis brings up a redis:7-alpine testcontainer and returns a connected
// *redis.Client; the container is terminated and the client closed via
// t.Cleanup. Sibling of db.StartPostgres. Prefer StartSharedRedis (one container
// per package via a TestMain) for suites with several Redis-backed tests.
func StartRedis(tb testing.TB, ctx context.Context) *redis.Client {
	tb.Helper()
	c, client, err := runRedis(ctx)
	if err != nil {
		tb.Fatalf("%v", err)
	}
	tb.Cleanup(func() {
		if termErr := c.Terminate(context.Background()); termErr != nil {
			tb.Logf("terminate redis: %v", termErr)
		}
	})
	tb.Cleanup(func() { _ = client.Close() })
	return client
}

// SharedRedis is a single redis:7-alpine container reset to an empty keyspace
// between tests via FLUSHDB. It is the cache analogue of db.SharedPostgres: built
// once from a package's TestMain so container startup is paid once per package,
// then reset before each test. Redis is schema-free, so the reset is a FLUSHDB
// (the analogue of Postgres Snapshot/Restore) rather than a template restore.
type SharedRedis struct {
	// Client addresses the shared Redis; it is stable across Reset, which clears
	// the keyspace without dropping the connection.
	Client *redis.Client
}

// Reset clears the shared Redis keyspace (FLUSHDB), discarding every key written
// by the previous test. Call it at the start of each Redis-backed test's setup. A
// FLUSHDB issued from this test-infra layer is fixture lifecycle — the cache
// analogue of SharedPostgres.Reset — not test arrange/assert state access.
func (s *SharedRedis) Reset(ctx context.Context) error {
	if err := s.Client.FlushDB(ctx).Err(); err != nil {
		return fmt.Errorf("flush shared redis: %w", err)
	}
	return nil
}

// StartSharedRedis runs one redis:7-alpine container and returns a handle plus a
// cleanup func for the caller (TestMain) to defer. Redis is schema-free, so there
// is no migrate/snapshot step; the per-test reset is (*SharedRedis).Reset
// (FLUSHDB). Sibling of db.StartSharedPostgres.
func StartSharedRedis(ctx context.Context, logger *slog.Logger) (*SharedRedis, func(), error) {
	c, client, err := runRedis(ctx)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		if closeErr := client.Close(); closeErr != nil {
			logger.Warn("close shared redis", "err", closeErr)
		}
		if termErr := c.Terminate(context.Background()); termErr != nil {
			logger.Warn("terminate shared redis", "err", termErr)
		}
	}
	return &SharedRedis{Client: client}, cleanup, nil
}

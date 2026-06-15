// Package testutil hosts cross-cutting test helpers shared by services and
// internal packages. Helpers here MUST NOT import service-side code; they are
// consumed by both Exchange- and Broker-side test trees, so the dependency
// must flow inward only.
package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

// StartRedis brings up a redis:7-alpine testcontainer and returns a connected
// *redis.Client. The container is torn down and the client closed via
// t.Cleanup. Mirror of sharedb.StartPostgres in internal/db/testing.go so the
// two read as siblings.
//
// Replaces the duplicate startRedis helpers previously copy-pasted into
// internal/httpsig/integration_test.go and
// src/broker/internal/transport/testutil_test.go (review finding L17).
func StartRedis(tb testing.TB, ctx context.Context) *redis.Client {
	tb.Helper()
	c, err := tcredis.Run(
		ctx, "redis:7-alpine",
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		tb.Fatalf("start redis: %v", err)
	}
	tb.Cleanup(func() {
		if termErr := c.Terminate(context.Background()); termErr != nil {
			tb.Logf("terminate redis: %v", termErr)
		}
	})
	dsn, err := c.ConnectionString(ctx)
	if err != nil {
		tb.Fatalf("redis conn string: %v", err)
	}
	opts, err := redis.ParseURL(dsn)
	if err != nil {
		tb.Fatalf("parse redis url: %v", err)
	}
	client := redis.NewClient(opts)
	if pingErr := client.Ping(ctx).Err(); pingErr != nil {
		tb.Fatalf("redis ping: %v", pingErr)
	}
	tb.Cleanup(func() { _ = client.Close() })
	return client
}

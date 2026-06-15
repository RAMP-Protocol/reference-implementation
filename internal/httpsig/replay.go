package httpsig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// ReplayStore records (keyID, signature) pairs that have already been
// verified, within a TTL window. A second SeenOrAdd with the same pair
// returns seen=true; the caller rejects the request as a replay.
type ReplayStore interface {
	SeenOrAdd(ctx context.Context, keyID, signature string, ttl time.Duration) (seen bool, err error)
}

// RedisReplayStore implements ReplayStore via SETNX + EX. Keys are namespaced
// under the configured prefix so the same Redis instance can host multiple
// replay-stores without collision (e.g. Broker + Exchange on a shared box).
type RedisReplayStore struct {
	client *redis.Client
	prefix string
}

// NewRedisReplayStore wraps client. prefix defaults to "httpsig:replay:".
func NewRedisReplayStore(client *redis.Client, prefix string) *RedisReplayStore {
	if prefix == "" {
		prefix = "httpsig:replay:"
	}
	return &RedisReplayStore{client: client, prefix: prefix}
}

// SeenOrAdd returns (false, nil) on first sight and (true, nil) on replay.
func (s *RedisReplayStore) SeenOrAdd(ctx context.Context, keyID, signature string, ttl time.Duration) (bool, error) {
	if s == nil || s.client == nil {
		return false, errors.New("httpsig: replay store not initialized")
	}
	// SET key value NX EX ttl returns "OK" on success, nil-reply when the
	// key already exists.
	res, err := s.client.SetArgs(ctx, s.prefix+replayKey(keyID, signature), "1", redis.SetArgs{
		Mode: "NX", TTL: ttl,
	}).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, fmt.Errorf("httpsig: redis set: %w", err)
	}
	if res == "OK" {
		return false, nil
	}
	return true, nil
}

// MemoryReplayStore is a map-backed replay store for tests and Redis-less dev.
// Not intended for production — there is no cross-process coordination.
type MemoryReplayStore struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	nowFn func() time.Time
}

// NewMemoryReplayStore returns a MemoryReplayStore. When nowFn is nil, the
// canonical clock.System{}.Now is used (ADR-008 D1).
func NewMemoryReplayStore(nowFn func() time.Time) *MemoryReplayStore {
	if nowFn == nil {
		nowFn = clock.System{}.Now
	}
	return &MemoryReplayStore{seen: map[string]time.Time{}, nowFn: nowFn}
}

// SeenOrAdd returns (false, nil) on first sight and (true, nil) on replay.
// Entries whose TTL has elapsed are treated as fresh.
func (s *MemoryReplayStore) SeenOrAdd(_ context.Context, keyID, signature string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFn()
	key := replayKey(keyID, signature)
	exp, ok := s.seen[key]
	if ok && exp.After(now) {
		return true, nil
	}
	s.seen[key] = now.Add(ttl)
	s.sweepLocked(now)
	return false, nil
}

// sweepLocked drops expired entries so the map cannot grow unbounded across
// a long-running test fixture. Called under s.mu.
func (s *MemoryReplayStore) sweepLocked(now time.Time) {
	for k, exp := range s.seen {
		if !exp.After(now) {
			delete(s.seen, k)
		}
	}
}

// replayKey hashes (keyID, signature) so the Redis key is bounded in size
// regardless of the Signature header length.
func replayKey(keyID, signature string) string {
	sum := sha256.Sum256([]byte(keyID + "\x00" + signature))
	return hex.EncodeToString(sum[:])
}

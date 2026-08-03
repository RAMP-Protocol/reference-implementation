// Package replay provides RFC 9421 nonce-dedup stores for RAMP services.
//
// Two replay-check interfaces are in play:
//
//   - Store (this package): the 3-argument form used by the bespoke relay
//     routes (broker /broker/v1/exchange/*). The relay caller supplies keyID
//     and signature separately so the store hashes them into a bounded key;
//     relay routes also use a two-phase Seen check before committing, to avoid
//     burning replay keys on a partially-invalid multisig request.
//
//   - core.ReplayStore (sdk/go/core): the 2-argument form expected by
//     connectserver.WithReplayStore. The nonce is the Content-Digest header
//     value, supplied and hashed by the connectserver orchestrator.
//
// RedisStore and MemoryStore implement Store. Use CoreAdapter to wrap either
// as a core.ReplayStore for connectserver wiring.
package replay

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

// ReplayTTL is the window during which a nonce is considered replayed. Matches
// the 5-minute window the RAMP RFC 9421 policy requires.
const ReplayTTL = 5 * time.Minute

// Store is the 3-argument replay interface used by bespoke relay routes. The
// relay caller supplies keyID and signature separately so the store hashes
// them into a bounded key. The two-phase Seen check (check all before
// committing any) prevents burning replay keys on partially-invalid multisig
// requests.
type Store interface {
	SeenOrAdd(ctx context.Context, keyID, signature string, ttl time.Duration) (seen bool, err error)
	// Seen reports whether (keyID, signature) is already recorded, WITHOUT
	// adding it.
	Seen(ctx context.Context, keyID, signature string) (seen bool, err error)
}

// RedisStore implements Store via SETNX + EX. Keys are namespaced under the
// configured prefix so the same Redis instance can host multiple replay stores
// without collision (e.g. Broker execute relay and Broker discover relay).
type RedisStore struct {
	client *redis.Client
	prefix string
}

// NewRedisStore wraps client. prefix defaults to "ramp:replay:".
func NewRedisStore(client *redis.Client, prefix string) *RedisStore {
	if prefix == "" {
		prefix = "ramp:replay:"
	}
	return &RedisStore{client: client, prefix: prefix}
}

// SeenOrAdd implements Store (3-arg). Returns (false, nil) on first sight and
// (true, nil) on replay. The key is the SHA-256 hash of keyID+"\x00"+signature.
func (s *RedisStore) SeenOrAdd(ctx context.Context, keyID, signature string, ttl time.Duration) (bool, error) {
	if s == nil || s.client == nil {
		return false, errors.New("replay: redis store not initialized")
	}
	res, err := s.client.SetArgs(ctx, s.prefix+replayKey(keyID, signature), "1", redis.SetArgs{
		Mode: "NX", TTL: ttl,
	}).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, fmt.Errorf("replay: redis set: %w", err)
	}
	return res != "OK", nil
}

// Seen implements Store (read-only EXISTS).
func (s *RedisStore) Seen(ctx context.Context, keyID, signature string) (bool, error) {
	if s == nil || s.client == nil {
		return false, errors.New("replay: redis store not initialized")
	}
	n, err := s.client.Exists(ctx, s.prefix+replayKey(keyID, signature)).Result()
	if err != nil {
		return false, fmt.Errorf("replay: redis exists: %w", err)
	}
	return n > 0, nil
}

// MemoryStore is a map-backed replay store for tests and Redis-less dev. Not
// intended for production — there is no cross-process coordination.
type MemoryStore struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	nowFn func() time.Time
}

// NewMemoryStore returns a MemoryStore. When nowFn is nil, clock.System{}.Now
// is used (ADR-008 D1).
func NewMemoryStore(nowFn func() time.Time) *MemoryStore {
	if nowFn == nil {
		nowFn = clock.System{}.Now
	}
	return &MemoryStore{seen: map[string]time.Time{}, nowFn: nowFn}
}

// NewStore returns a Redis-backed store when client is non-nil, else an
// in-memory one — the backend selection every replay-guarded surface makes. It
// returns a FRESH store per call, so each surface keeps its own prefix-scoped
// instance (never a shared singleton).
func NewStore(client *redis.Client, prefix string) Store {
	if client != nil {
		return NewRedisStore(client, prefix)
	}
	return NewMemoryStore(nil)
}

// SeenOrAdd implements Store (3-arg). Returns (false, nil) on first sight and
// (true, nil) on replay. Entries whose TTL has elapsed are treated as fresh.
func (s *MemoryStore) SeenOrAdd(_ context.Context, keyID, signature string, ttl time.Duration) (bool, error) {
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

// Seen implements Store (read-only, unexpired check).
func (s *MemoryStore) Seen(_ context.Context, keyID, signature string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.seen[replayKey(keyID, signature)]
	return ok && exp.After(s.nowFn()), nil
}

// sweepLocked drops expired entries so the map cannot grow unbounded across
// a long-running test fixture. Called under s.mu.
func (s *MemoryStore) sweepLocked(now time.Time) {
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

// CoreAdapter wraps a Store to satisfy core.ReplayStore. The connectserver
// supplies a per-verified-signature nonce (keyid + signature bytes); CoreAdapter
// treats the nonce as a key-only lookup (keyID=nonce, signature="") so the
// underlying store hashes it to a deterministic bounded key. Use this to wire a
// pre-built Store to connectserver.WithReplayStore.
type CoreAdapter struct {
	inner Store
}

// NewCoreAdapter wraps inner. The TTL is supplied by the SDK on each SeenOrAdd
// call (the SDK decides the window; the app supplies the store via WithReplayStore).
func NewCoreAdapter(inner Store) *CoreAdapter {
	return &CoreAdapter{inner: inner}
}

// Seen implements core.ReplayStore's read-only phase: the SDK checks every
// signature's nonce before committing any of them.
func (a *CoreAdapter) Seen(ctx context.Context, nonce string) (bool, error) {
	return a.inner.Seen(ctx, nonce, "")
}

// SeenOrAdd implements core.ReplayStore. The nonce is treated as keyID;
// signature is empty. The underlying Store hashes both into a single bounded key.
func (a *CoreAdapter) SeenOrAdd(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
	return a.inner.SeenOrAdd(ctx, nonce, "", ttl)
}

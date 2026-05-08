// Package budget enforces per-license spending caps across periods.
//
// The Broker checks a caller's period budget before committing to an
// Exchange transaction. Counters live in Redis keyed by license + period
// (e.g. "budget:lic-42:2026-04"); when Redis is not configured, an
// in-memory map is used for demo environments.
package budget

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Period granularity. Monthly matches enterprise billing cadence and is
// coarse enough for demo flows; fine-grained caps would be added later.
const periodLayout = "2006-01"

// ErrExhausted indicates the budget cap would be exceeded.
var ErrExhausted = errors.New("budget: period cap exceeded")

// Decision carries the outcome of a Check call.
type Decision struct {
	Allowed   bool
	Remaining int64
	Limit     int64
	Consumed  int64
}

// Service exposes Check + Record semantics to handlers.
type Service interface {
	Check(ctx context.Context, licenseID string, limitMinor int64) (Decision, error)
	Record(ctx context.Context, licenseID string, costMinor int64) error
}

// RedisService is the Redis-backed implementation.
type RedisService struct {
	client *redis.Client
	ttl    time.Duration
	now    func() time.Time
}

// NewRedis constructs a RedisService; ttl is how long period counters persist.
func NewRedis(client *redis.Client, ttl time.Duration) *RedisService {
	if ttl <= 0 {
		ttl = 35 * 24 * time.Hour
	}
	return &RedisService{client: client, ttl: ttl, now: func() time.Time { return time.Now().UTC() }}
}

// Check returns the budget decision without mutating state.
func (s *RedisService) Check(ctx context.Context, licenseID string, limitMinor int64) (Decision, error) {
	key := s.key(licenseID)
	consumed, err := s.readConsumed(ctx, key)
	if err != nil {
		return Decision{}, err
	}
	remaining := limitMinor - consumed
	return Decision{
		Allowed:   remaining >= 0,
		Remaining: remaining,
		Limit:     limitMinor,
		Consumed:  consumed,
	}, nil
}

// Record increments the period counter after a transaction completes.
func (s *RedisService) Record(ctx context.Context, licenseID string, costMinor int64) error {
	if costMinor <= 0 {
		return nil
	}
	key := s.key(licenseID)
	pipe := s.client.TxPipeline()
	pipe.IncrBy(ctx, key, costMinor)
	pipe.Expire(ctx, key, s.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("budget: incr: %w", err)
	}
	return nil
}

func (s *RedisService) readConsumed(ctx context.Context, key string) (int64, error) {
	v, err := s.client.Get(ctx, key).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("budget: read: %w", err)
	}
	return v, nil
}

func (s *RedisService) key(licenseID string) string {
	return fmt.Sprintf("budget:%s:%s", licenseID, s.now().Format(periodLayout))
}

// MemoryService is the in-process fallback used when Redis is not configured.
type MemoryService struct {
	mu     sync.Mutex
	counts map[string]int64
	now    func() time.Time
}

// NewMemory constructs a MemoryService.
func NewMemory() *MemoryService {
	return &MemoryService{counts: make(map[string]int64), now: func() time.Time { return time.Now().UTC() }}
}

// Check reports the budget decision without mutating state.
func (s *MemoryService) Check(_ context.Context, licenseID string, limitMinor int64) (Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	consumed := s.counts[s.key(licenseID)]
	remaining := limitMinor - consumed
	return Decision{
		Allowed:   remaining >= 0,
		Remaining: remaining,
		Limit:     limitMinor,
		Consumed:  consumed,
	}, nil
}

// Record increments the counter for the current period.
func (s *MemoryService) Record(_ context.Context, licenseID string, costMinor int64) error {
	if costMinor <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[s.key(licenseID)] += costMinor
	return nil
}

func (s *MemoryService) key(licenseID string) string {
	return fmt.Sprintf("budget:%s:%s", licenseID, s.now().Format(periodLayout))
}

// Select returns a Service backed by Redis when client != nil, memory otherwise.
func Select(client *redis.Client, ttl time.Duration) Service {
	if client == nil {
		return NewMemory()
	}
	return NewRedis(client, ttl)
}

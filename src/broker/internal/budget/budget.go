// Package budget enforces per-agent spending caps across periods.
//
// The Broker checks an agent's period budget before returning licensed offers,
// keyed on the AUTHENTICATED agent identity (never the caller-written
// billing_ref). Counters live in Redis keyed by that identity + period
// (e.g. "budget:agent-42:2026-04"); when Redis is not configured, an
// in-memory map is used for demo environments.
package budget

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
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
//
// All money parameters and Decision fields are 1e8 FIXED-POINT int64 (8dp), NOT
// minor units / cents (DECISION 1+3). The caller scales canonical wire money
// strings to fixed-point at the transport boundary (moneyStringToFixedPoint) so
// fractions of a cent are accounted EXACTLY while the Redis INCRBY counter stays
// an atomic integer. The parameter names (limitMinor/costMinor) are retained to
// avoid churn; the unit is fixed-point 1e8, not minor units.
type Service interface {
	Check(ctx context.Context, agentID string, limitMinor int64) (Decision, error)
	Record(ctx context.Context, agentID string, costMinor int64) error
}

// RedisService is the Redis-backed implementation.
type RedisService struct {
	client *redis.Client
	ttl    time.Duration
	clk    clock.Clock
}

// NewRedis constructs a RedisService; ttl is how long period counters persist.
// clk is the time source consulted to derive the period bucket — production
// wires clock.System{}, tests inject a DeterministicClock.
func NewRedis(client *redis.Client, ttl time.Duration, clk clock.Clock) *RedisService {
	if ttl <= 0 {
		ttl = 35 * 24 * time.Hour
	}
	if clk == nil {
		clk = clock.System{}
	}
	return &RedisService{client: client, ttl: ttl, clk: clk}
}

// Check returns the budget decision without mutating state.
func (s *RedisService) Check(ctx context.Context, agentID string, limitMinor int64) (Decision, error) {
	key := s.key(agentID)
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
func (s *RedisService) Record(ctx context.Context, agentID string, costMinor int64) error {
	if costMinor <= 0 {
		return nil
	}
	key := s.key(agentID)
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

func (s *RedisService) key(agentID string) string {
	return fmt.Sprintf("budget:%s:%s", agentID, s.clk.Now().Format(periodLayout))
}

// MemoryService is the in-process fallback used when Redis is not configured.
type MemoryService struct {
	mu     sync.Mutex
	counts map[string]int64
	clk    clock.Clock
}

// NewMemory constructs a MemoryService. clk drives the period bucket
// derivation; pass clock.System{} in production, a DeterministicClock
// in tests.
func NewMemory(clk clock.Clock) *MemoryService {
	if clk == nil {
		clk = clock.System{}
	}
	return &MemoryService{counts: make(map[string]int64), clk: clk}
}

// Check reports the budget decision without mutating state.
func (s *MemoryService) Check(_ context.Context, agentID string, limitMinor int64) (Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	consumed := s.counts[s.key(agentID)]
	remaining := limitMinor - consumed
	return Decision{
		Allowed:   remaining >= 0,
		Remaining: remaining,
		Limit:     limitMinor,
		Consumed:  consumed,
	}, nil
}

// Record increments the counter for the current period.
func (s *MemoryService) Record(_ context.Context, agentID string, costMinor int64) error {
	if costMinor <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[s.key(agentID)] += costMinor
	return nil
}

func (s *MemoryService) key(agentID string) string {
	return fmt.Sprintf("budget:%s:%s", agentID, s.clk.Now().Format(periodLayout))
}

// Select returns a Service backed by Redis when client != nil, memory otherwise.
// clk is the time source consulted for period-bucket derivation.
func Select(client *redis.Client, ttl time.Duration, clk clock.Clock) Service {
	if client == nil {
		return NewMemory(clk)
	}
	return NewRedis(client, ttl, clk)
}

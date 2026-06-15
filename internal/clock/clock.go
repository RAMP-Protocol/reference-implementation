// Package clock realises ADR-008 D1 (time as a port).
//
// Production policy code MUST consult time through the Clock interface
// rather than calling time.Now / time.Since / time.Until directly. The
// forbidigo linter (configured under the policy trees) enforces the
// ban; this package and a small set of allowlisted leaves (production
// roots, observability shims, log formatters) are the only places
// allowed to construct or read the wall clock.
//
// Tests construct DeterministicClock and advance it explicitly so
// behaviour-gating windows (attenuation TTL ≤10m, authority valid_until,
// reporting grace, cache TTL) are exercised without sleeping.
package clock

import (
	"sync"
	"time"
)

// Clock is the canonical time port. Implementations MUST return UTC
// instants; callers rely on UTC semantics for window comparisons. The
// After scheduling primitive is included so deterministic implementations
// can drive scheduled wakeups without real wall-clock latency.
type Clock interface {
	// Now returns the current instant in UTC.
	Now() time.Time
	// After returns a channel that receives a single value once d has
	// elapsed on this clock. Deterministic implementations fire on Advance
	// rather than on real time.
	After(d time.Duration) <-chan time.Time
}

// System is the production implementation; it consults the wall clock.
// This is one of the few sites permitted to call time.Now directly —
// the forbidigo allowlist exempts internal/clock.
type System struct{}

// Now returns the current UTC instant from the wall clock.
func (System) Now() time.Time { return time.Now().UTC() } //nolint:forbidigo // sole production allowlist

// After delegates to the standard library timer.
func (System) After(d time.Duration) <-chan time.Time { return time.After(d) }

// NewSystem returns a System clock value. Provided as a constructor so
// wiring code can write `clock.NewSystem()` symmetrically with
// `clock.NewDeterministic(...)`.
func NewSystem() Clock { return System{} }

// DeterministicClock is the test-side implementation. The instant is
// fixed at construction time and only advances when the test calls
// Advance or SetNow. Concurrent reads are safe; concurrent advance from
// multiple goroutines is serialised by the embedded mutex.
type DeterministicClock struct {
	mu      sync.Mutex
	now     time.Time
	pending []pendingTimer
}

type pendingTimer struct {
	fireAt time.Time
	ch     chan time.Time
}

// NewDeterministic constructs a DeterministicClock anchored at start.
// Tests typically pass a fixed UTC instant such as
// `time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)`.
func NewDeterministic(start time.Time) *DeterministicClock {
	return &DeterministicClock{now: start.UTC()}
}

// Now returns the clock's current instant. The returned value is the
// same UTC time as the most recent Advance / SetNow.
func (c *DeterministicClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d and fires any After channels
// whose scheduled instant is now reached. d MUST be non-negative; a
// negative value is treated as zero so accidental rewinds cannot
// silently break window invariants.
func (c *DeterministicClock) Advance(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	due := c.now
	remaining := c.pending[:0]
	for _, t := range c.pending {
		if !t.fireAt.After(due) {
			t.ch <- due
			close(t.ch)
			continue
		}
		remaining = append(remaining, t)
	}
	c.pending = remaining
	c.mu.Unlock()
}

// SetNow pins the clock to instant; pending After channels whose target
// is now reached fire immediately. Useful when a test needs to jump to
// a specific cliff (e.g. exactly the authority valid_until) rather than
// step forward by a relative duration.
func (c *DeterministicClock) SetNow(instant time.Time) {
	c.mu.Lock()
	c.now = instant.UTC()
	due := c.now
	remaining := c.pending[:0]
	for _, t := range c.pending {
		if !t.fireAt.After(due) {
			t.ch <- due
			close(t.ch)
			continue
		}
		remaining = append(remaining, t)
	}
	c.pending = remaining
	c.mu.Unlock()
}

// After returns a channel that receives once Advance / SetNow brings
// the clock to or past now()+d. Buffered length 1 so Advance never
// blocks even if the test never reads the channel.
func (c *DeterministicClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if d <= 0 {
		ch <- c.now
		close(ch)
		return ch
	}
	c.pending = append(c.pending, pendingTimer{fireAt: c.now.Add(d), ch: ch})
	return ch
}
